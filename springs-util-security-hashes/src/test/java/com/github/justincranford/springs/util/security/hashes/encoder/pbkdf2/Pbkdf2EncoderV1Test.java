package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
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
	private static final Pbkdf2Algorithm PRF = Pbkdf2Algorithm.PBKDF2WithHmacSHA256;
	private static final HashEncodeDecode HED = HashEncodeDecode.STD_CB_SALT_OTH; // encode options: Base64, colon+bar separators, salt+other parameters included
	private static final Pbkdf2EncoderV1 FAST_PBKDF2 = new Pbkdf2EncoderV1(PRF, 1, 32, HED);

	@Nested
	public class EncodePwd {
		private static final String PWD = "P@ssw0rd";
		private static final Function<CharSequence, byte[]> RANDOM_SALT_SUPPLIER =
			(charSequence) -> SecureRandomUtil.randomBytes(16); // independent of input value

		// saltBytes => randomSaltBytes
		@Test
		public void testRandomSalt_saltHasHighEntropy() {
			assertNonDeterministic(computePbkdf2s(REPEATS, FAST_PBKDF2, PWD, RANDOM_SALT_SUPPLIER));
		}
	}

	@Nested
	public class EncodePii {
		private static final String PII = "Hello.World@example.com";

		@Nested
		public class ConstantSalt {
			private static final byte[] CONSTANT_SALT_BYTES = SecureRandomUtil.randomBytes(16);
			final Function<CharSequence, byte[]> CONSTANT_SALT_SUPPLIER =
				(charSequence) -> CONSTANT_SALT_BYTES; // independent of input value

			// saltBytes => constantSaltBytes
			@Test
			public void testConstantSalt_saltHasNoEntropy() {
				assertDeterministic(computePbkdf2s(REPEATS, FAST_PBKDF2, PII, CONSTANT_SALT_SUPPLIER));
			}
		}

		@Nested
		public class SaltDerivedFromPii {
			private static final MacAlgorithm DERIVE_MAC = MacAlgorithm.HmacSHA256; // only used for derive, not for random||constant tests
			private static final byte[] CONSTANT_SEED_BYTES = SecureRandomUtil.randomBytes(16); // treat input salt as a seed

			// saltBytes => HmacSha256(SecretKey(piiBytes), piiBytes+constantSeedBytes)
			@Test
			public void testDerivedSalt_saltHasLowEntropy() {
				final Function<CharSequence, byte[]> deriveSaltFromPasswordSeed = (charSequence) -> {
					final byte[] charSequenceBytes = charSequence.toString().getBytes();
					final SecretKeySpec lowEntropyKey = new SecretKeySpec(charSequenceBytes, "PepperTheSalt");
					return DERIVE_MAC.compute(lowEntropyKey, ArrayUtil.concat(charSequenceBytes, CONSTANT_SEED_BYTES));
				};
				assertDeterministic(computePbkdf2s(REPEATS, FAST_PBKDF2, PII, deriveSaltFromPasswordSeed));
			}

			// saltBytes => HmacSha256(SecretKey(randomKeyBytes), piiBytes+constantSeedBytes)
			@Test
			public void testDerivedSalt_saltHasHighEntropy() {
				final SecretKeySpec highEntropyKey = new SecretKeySpec(SecureRandomUtil.randomBytes(32), "PepperTheSalt");
				final Function<CharSequence, byte[]> deriveSaltFromKeyPasswordSeed = (charSequence) -> {
					final byte[] charSequenceBytes = charSequence.toString().getBytes();
					return DERIVE_MAC.compute(highEntropyKey, ArrayUtil.concat(charSequenceBytes, CONSTANT_SEED_BYTES));
				};
				assertDeterministic(computePbkdf2s(REPEATS, FAST_PBKDF2, PII, deriveSaltFromKeyPasswordSeed));
			}
		}
	}

	private void assertDeterministic(final Set<String> hashes) {
		log.info("hashes: {}", hashes);
		assertThat(hashes.size()).isEqualTo(1);
	}

	private void assertNonDeterministic(final Set<String> hashes) {
		log.info("hashes: {}", hashes);
		assertThat(hashes.size()).isEqualTo(REPEATS);
	}

	private Set<String> computePbkdf2s(final int repeats, final Pbkdf2EncoderV1 parameters, final CharSequence charSequence, final Function<CharSequence, byte[]> saltSupplier) {
		final Set<String> encodedHashes = new HashSet<>();
		for (int i = 0; i < repeats; i++) {
			final byte[] saltBytes = saltSupplier.apply(charSequence);
			final byte[] hashBytes = parameters.computeHash(saltBytes, charSequence);
			encodedHashes.add(Base64Util.Constants.STD_ENCODER.encodeToString(hashBytes));
		}
		return encodedHashes;
	}
}
