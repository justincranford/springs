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
 * Demo concept of random salt, constant salt, and derived salts.
 */
@Slf4j
@SuppressWarnings({"nls", "static-method"})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class Pbkdf2EncoderV1Test {
	private static final int REPEATS = 3; // repeat hashing within a test to verify if hashes are determinstic vs non-deterministic
	private static final Pbkdf2EncoderV1 FAST_PBKDF2 = new Pbkdf2EncoderV1(Pbkdf2Algorithm.PBKDF2WithHmacSHA256, 1, 32, HashEncodeDecode.STD_CB_SALT_OTH);
	private static final String PII = "Hello.World@example.com";
	private static final String PWD = "P@ssw0rd";

	@Nested
	public class EncodePwd { // classic Pbkdf2 usage with random salt
		private static final Function<CharSequence, byte[]> RANDOM_SALT_SUPPLIER =
			(charSequence) -> SecureRandomUtil.randomBytes(16); // independent of input value

		@Test
		public void testRandomSalt_saltHasHighEntropy() {
			final Set<String> hashes = computePbkdf2s(REPEATS, FAST_PBKDF2, PWD, RANDOM_SALT_SUPPLIER);
			log.info("hashes: {}", hashes);
			assertThat(hashes.size()).isEqualTo(REPEATS); // non-deterministic
		}
	}

	@Nested
	public class EncodePii {
		@Nested
		public class ConstantSalt { // naive Pbkdf2 usage with constant salt (vulnerable to rainbow table attack)
			private static final byte[] CONSTANT_SALT_BYTES = SecureRandomUtil.randomBytes(16);
			private static final Function<CharSequence, byte[]> CONSTANT_SALT_SUPPLIER =
				(charSequence) -> CONSTANT_SALT_BYTES; // independent of input value

			@Test
			public void testConstantSalt_saltHasNoEntropy() {
				final Set<String> hashes = computePbkdf2s(REPEATS, FAST_PBKDF2, PII, CONSTANT_SALT_SUPPLIER);
				log.info("hashes: {}", hashes);
				assertThat(hashes.size()).isEqualTo(1); // deterministic
			}
		}

		// advanced Pbkdf2 usage with derived salt (entropy correlated to passwords (no key) or key+passwords)
		@Nested
		public class SaltDerivedFromPii {
			private static final MacAlgorithm DERIVE_MAC = MacAlgorithm.HmacSHA256; // only used for derive, not for random||constant tests
			private static final byte[] CONSTANT_SEED_BYTES = SecureRandomUtil.randomBytes(16); // treat input salt as a seed

			@Test
			public void testDerivedSalt_saltHasLowEntropy() { // saltBytes => HmacSha256(SecretKey(piiBytes), piiBytes+constantSeedBytes)
				final Function<CharSequence, byte[]> deriveSaltFromPasswordSeed = (charSequence) -> {
					final byte[] charSequenceBytes = charSequence.toString().getBytes(); // no key => use password as the key
					final SecretKeySpec lowEntropyKey = new SecretKeySpec(charSequenceBytes, "PepperTheSalt");
					return DERIVE_MAC.compute(lowEntropyKey, ArrayUtil.concat(charSequenceBytes, CONSTANT_SEED_BYTES));
				};
				final Set<String> hashes = computePbkdf2s(REPEATS, FAST_PBKDF2, PII, deriveSaltFromPasswordSeed);
				log.info("hashes: {}", hashes);
				assertThat(hashes.size()).isEqualTo(1); // deterministic
			}

			@Test
			public void testDerivedSalt_saltHasHighEntropy() { // saltBytes => HmacSha256(SecretKey(randomKeyBytes), piiBytes+constantSeedBytes)
				final SecretKeySpec highEntropyKey = new SecretKeySpec(SecureRandomUtil.randomBytes(32), "PepperTheSalt");
				final Function<CharSequence, byte[]> deriveSaltFromKeyPasswordSeed = (charSequence) -> {
					final byte[] charSequenceBytes = charSequence.toString().getBytes();
					return DERIVE_MAC.compute(highEntropyKey, ArrayUtil.concat(charSequenceBytes, CONSTANT_SEED_BYTES));
				};
				final Set<String> hashes = computePbkdf2s(REPEATS, FAST_PBKDF2, PII, deriveSaltFromKeyPasswordSeed);
				log.info("hashes: {}", hashes);
				assertThat(hashes.size()).isEqualTo(1); // deterministic
			}
		}
	}

	private Set<String> computePbkdf2s(final int repeats, final Pbkdf2EncoderV1 parameters, final CharSequence charSequence, final Function<CharSequence, byte[]> saltSupplier) {
		final Set<String> encodedHashes = new HashSet<>();
		for (int i = 0; i < repeats; i++) {
			final byte[] saltBytes = saltSupplier.apply(charSequence); // derive salt from charSequence (or not)
			final byte[] hashBytes = parameters.computeHash(saltBytes, charSequence);
			encodedHashes.add(HexFormat.of().formatHex(hashBytes)); // byte[].toString() not very helful, so use something else
		}
		return encodedHashes;
	}
}
