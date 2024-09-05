package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import java.util.function.Function;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashEncodeDecode;
import com.github.justincranford.springs.util.security.hashes.mac.MacAlgorithm;

import lombok.extern.slf4j.Slf4j;

/**
 * Demo how to hash with random salt, constant salt, derived size (PII as key), and derived size (random key).
 * The strength of each approach depends on how big of a Rainbox table is needed to attack it. 
 *  - Rainbox table size = NumUnique(Salt) * NumUnique(Input)
 * Quadratic sizing is good. Linear sizing is bad.
 */
@Slf4j
@SuppressWarnings({"nls", "static-method"})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Pbkdf2EncoderV1Test {
	private static final int HASH_REPEATS = 3; // repeat hashing in each test; 1 unique output means deterministic, N different outputs means non-deterministic
	private static final Pbkdf2EncoderV1 FAST_PBKDF2 = new Pbkdf2EncoderV1(Pbkdf2Algorithm.PBKDF2WithHmacSHA256, 1, 32, HashEncodeDecode.STD_CB_SALT_OTH);
	private static final String PII = "Hello.World@example.com";
	private static final String PWD = "P@ssw0rd";

	
	@Nested
	public class EncodePwd {
		/**
		 * Ideal Pbkdf2 usage with random salt. Rainbox table size is quadratic; NumUnique(Salt) * NumUnique(PWD).
		 */
		@Nested
		public class RandomSalt {
			private static final Function<CharSequence, byte[]> RANDOM_SALT_SUPPLIER = (charSequence) -> SecureRandomUtil.randomBytes(64); // doesn't need to be secret

			@Test
			public void quadraticSearchSpaceForSalt() {
				final Set<String> hashes = computeHashMultipleTimes(HASH_REPEATS, FAST_PBKDF2, PWD, RANDOM_SALT_SUPPLIER);
				log.info("hashes: {}", hashes);
				assertThat(hashes.size()).isEqualTo(HASH_REPEATS); // non-deterministic
			}
		}
	}

	@Nested
	public class EncodePii {
		/**
		 * Weak Pbkdf2 usage with constant salt. Rainbox table size is linear; 1 * NumUnique(PWD).
		 */
		@Nested
		public class ConstantSalt {
			private static final byte[] CONSTANT_SALT_BYTES = SecureRandomUtil.randomBytes(64); // needs to be secret
			private static final Function<CharSequence, byte[]> CONSTANT_SALT_SUPPLIER = (charSequence) -> CONSTANT_SALT_BYTES;

			@Test
			public void linearSearchSpaceForSalt() {
				final Set<String> hashes = computeHashMultipleTimes(HASH_REPEATS, FAST_PBKDF2, PII, CONSTANT_SALT_SUPPLIER);
				log.info("hashes: {}", hashes);
				assertThat(hashes.size()).isEqualTo(1); // verify outputs are non-deterministic
			}
		}

		/**
		 * Weak Pbkdf2 usage with derived salt, using PII as Hmac key. Rainbox table size is still linear; 1 * NumUnique(PWD). Strength is same as using constant salt. 
		 */
		@Nested
		public class DerivedSaltWithPiiAsKey {
			private static final byte[] CONSTANT_SALT_SEED_BYTES = SecureRandomUtil.randomBytes(64); // needs to be secret
			private static final MacAlgorithm PEPPER_ALG = MacAlgorithm.HmacSHA256;
			private static final Function<CharSequence, byte[]> DERIVED_SALT_SUPPLIER = (charSequence) -> {
				final SecretKeySpec piiAsKey = new SecretKeySpec(charSequence.toString().getBytes(), "PepperTheSalt"); // no key => use PII input as the key
				return PEPPER_ALG.compute(piiAsKey, ArrayUtil.concat(charSequence.toString().getBytes(), CONSTANT_SALT_SEED_BYTES));
			};

			@Test
			public void linearSearchSpaceForSalt() { // saltBytes => HmacSha256(SecretKey(piiBytes), piiBytes+constantSeedBytes)
				final Set<String> hashes = computeHashMultipleTimes(HASH_REPEATS, FAST_PBKDF2, PII, DERIVED_SALT_SUPPLIER);
				log.info("hashes: {}", hashes);
				assertThat(hashes.size()).isEqualTo(1); // verify outputs are deterministic
			}
		}

		/**
		 * Strong Pbkdf2 usage with derived salt, using random Hmac key. Rainbox table size is quadratic; NumUnique(Salt) * NumUnique(PWD).
		 * NumUnique(Salt) correlates to Hmac output search space, which depends on Hmac key size and the Hmac algorithm. Examples:
		 *  - HmacWithSha256 with minimum 32-byte key => ~32-byte search space 
		 *  - HmacWithSha512 with minimum 64-byte key => ~64-byte search space
		 * Hashing introduces a slightly higher chance of collisions versus random bytes. However, the redunction is security is likely small.
		 */
		@Nested
		public class DerivedSaltWithRandomKey {
			private static final byte[] CONSTANT_SALT_SEED_BYTES = SecureRandomUtil.randomBytes(64); // doesn't need to be secret
			private static final MacAlgorithm PEPPER_ALG = MacAlgorithm.HmacSHA256;
			private static final SecretKeySpec RANDOM_HMAC_KEY = new SecretKeySpec(SecureRandomUtil.randomBytes(64), "PepperTheSalt"); // needs to be secret
			private static final  Function<CharSequence, byte[]> DERIVED_SALT_SUPPLIER = (charSequence) -> {
				return PEPPER_ALG.compute(RANDOM_HMAC_KEY, ArrayUtil.concat(charSequence.toString().getBytes(), CONSTANT_SALT_SEED_BYTES));
			};

			@Test
			public void quadraticSearchSpaceForSalt() { // saltBytes => HmacSha256(SecretKey(randomKeyBytes), piiBytes+constantSeedBytes)
				final Set<String> hashes = computeHashMultipleTimes(HASH_REPEATS, FAST_PBKDF2, PII, DERIVED_SALT_SUPPLIER);
				log.info("hashes: {}", hashes);
				assertThat(hashes.size()).isEqualTo(1); // verify outputs are deterministic
			}
		}
	}

	private Set<String> computeHashMultipleTimes(final int repeats, final Pbkdf2EncoderV1 parameters, final CharSequence charSequence, final Function<CharSequence, byte[]> saltSupplier) {
		final Set<String> encodedHashes = new HashSet<>();
		for (int i = 0; i < repeats; i++) {
			final byte[] saltBytes = saltSupplier.apply(charSequence); // derive salt from charSequence (or not)
			final byte[] hashBytes = parameters.computeHash(saltBytes, charSequence);
			encodedHashes.add(HexFormat.of().formatHex(hashBytes)); // byte[].toString() not very helful, so use something else
		}
		return encodedHashes;
	}
}
