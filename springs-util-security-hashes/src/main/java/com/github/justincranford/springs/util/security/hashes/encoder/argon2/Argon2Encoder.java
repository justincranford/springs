package com.github.justincranford.springs.util.security.hashes.encoder.argon2;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.argon2.Argon2EncodingUtils.Argon2Hash;
import com.github.justincranford.springs.util.security.hashes.util.MessageDigestUtil;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public class Argon2Encoder {
	private static final String DERIVED_SALT_MESSAGE_DIGEST_ALGORITHM = "SHA-512"; // 512b/64B
	private static final int ARGON2_ALGORITHM_TYPE = Argon2Parameters.ARGON2_id;
	private static final int ARGON2_VERSION = Argon2Parameters.ARGON2_VERSION_13;

	public static class RandomSalt extends CustomArgon2Encoder {
		public RandomSalt(int randomSaltLength, byte[] associatedData, int hashLength, int parallelism, int memory, int iterations) {
			super(RandomSalt.class, (rawPassword) -> SecureRandomUtil.randomBytes(randomSaltLength), associatedData, hashLength, parallelism, memory, iterations);
		}
	}
	public static class DerivedSalt extends CustomArgon2Encoder {
		public DerivedSalt(int derivedSaltLength, byte[] associatedData, int hashLength, int parallelism, int memory, int iterations) {
			super(DerivedSalt.class, (rawPassword) -> derivedSalt(rawPassword, derivedSaltLength, associatedData, hashLength, parallelism, memory, iterations), associatedData, hashLength, parallelism, memory, iterations);
		}
	}
	public static class ConstantSalt extends CustomArgon2Encoder {
		public ConstantSalt(byte[] constantSalt, byte[] associatedData, int hashLength, int parallelism, int memory, int iterations) {
			super(ConstantSalt.class, (rawPassword) -> constantSalt, associatedData, hashLength, parallelism, memory, iterations);
		}
	}

	private static class CustomArgon2Encoder extends Argon2PasswordEncoder {
		private final Function<CharSequence, String> encode;
		private final BiFunction<CharSequence, String, Boolean> matches;
		private final Function<String, Boolean> upgradeEncoding;
		public CustomArgon2Encoder(
			final Class<? extends CustomArgon2Encoder> clazz,
			final Function<CharSequence, byte[]> saltSupplier,
			final byte[] associatedData,
			final int hashLength,
			final int parallelism,
			final int memory,
			final int iterations
		) {
			super(saltSupplier.apply("").length, hashLength, parallelism, memory, iterations);

			if (clazz.equals(ConstantSalt.class)) {
				final Argon2Parameters parameters = parameters(saltSupplier.apply(""), associatedData, parallelism, memory, iterations);
				this.encode = (rawPassword) ->  encodeHashNoParameters(computeHash(rawPassword, parameters, hashLength)); // exclude parameters from output
				this.matches = (rawPassword, encodedPassword) -> Boolean.valueOf(MessageDigest.isEqual(encode(rawPassword).getBytes(StandardCharsets.UTF_8), encodedPassword.getBytes(StandardCharsets.UTF_8)));
				this.upgradeEncoding = (encodedPassword) -> Boolean.FALSE; // never upgrade encoding when using constant salt
			} else {
				this.encode = (rawPassword) -> {
					final Argon2Parameters parameters = parameters(saltSupplier.apply(rawPassword), associatedData, parallelism, memory, iterations);
					return Argon2EncodingUtils.encode(computeHash(rawPassword, parameters, hashLength), parameters); // include parameters in output
				};
				this.matches = (rawPassword, encodedPassword) -> Boolean.valueOf(super.matches(rawPassword, encodedPassword));
				if (clazz.equals(DerivedSalt.class)) {
					this.upgradeEncoding = (encodedPassword) -> Boolean.FALSE; // never upgrade encoding when using derived salt
				} else if (clazz.equals(RandomSalt.class)) {
					this.upgradeEncoding = (encodedPassword) -> {
						if (encodedPassword == null || encodedPassword.length() == 0) {
							return Boolean.FALSE;
						}
						final Argon2Hash hashAndParameters = Argon2EncodingUtils.decode(encodedPassword); // conditionally upgrade encoding when using random salt
						final byte[] hash = hashAndParameters.getHash();
						final Argon2Parameters parameters = hashAndParameters.getParameters();
						return Boolean.valueOf(hash.length < hashLength || parameters.getLanes() < parallelism || parameters.getMemory() < memory || parameters.getIterations() < iterations);
					};
				} else {
					throw new RuntimeException("Unsupported class " + clazz.getCanonicalName());
				}
			}
		}

		@Override
		public String encode(final CharSequence rawPassword) {
			return this.encode.apply(rawPassword);
		}
		@Override
		public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
			return this.matches.apply(rawPassword, encodedPassword).booleanValue();
		}
		@Override
		public boolean upgradeEncoding(final String encodedPassword) {
			return this.upgradeEncoding.apply(encodedPassword).booleanValue();
		}
	}

	private static byte[] computeHash(final CharSequence rawPassword, final Argon2Parameters parameters, int hashLength) {
		final Argon2BytesGenerator generator = new Argon2BytesGenerator();
		generator.init(parameters);
		final byte[] hash = new byte[hashLength];
		generator.generateBytes(rawPassword.toString().toCharArray(), hash);
		return hash;
	}

	private static String encodeHashNoParameters(final byte[] hash) {
		return Base64Util.STD_ENCODE.string(hash);
	}

	public static byte[] derivedSalt(
		final CharSequence rawPassword,
		final int derivedSaltLength,
		final byte[] associatedData,
		final int hashLength,
		final int parallelism,
		final int memory,
		final int iterations
	) {
		return MessageDigestUtil.messageDigest(
			DERIVED_SALT_MESSAGE_DIGEST_ALGORITHM,
			canonicalEncodeDerivedSaltParameters(rawPassword, derivedSaltLength, associatedData, hashLength, parallelism, memory, iterations)
		);
	}

	private static byte[] canonicalEncodeDerivedSaltParameters(
		final CharSequence rawPassword,
		final int derivedSaltLength,
		final byte[] associatedData,
		final int hashLength,
		final int parallelism,
		final int memory,
		final int iterations
	) {
		return ByteBuffer.allocate(rawPassword.length() + associatedData.length + 28)
			.order(ByteOrder.BIG_ENDIAN)
			.put(rawPassword.toString().getBytes(StandardCharsets.UTF_8)) // different derived salt per different password
			.putInt(ARGON2_VERSION)
			.putInt(derivedSaltLength)
			.put(associatedData)
			.putInt(ARGON2_ALGORITHM_TYPE)
			.putInt(hashLength)
			.putInt(parallelism)
			.putInt(memory)
			.putInt(iterations)
			.array();
	}

	private static Argon2Parameters parameters(final byte[] salt, final byte[] associatedData, int parallelism, int memory, int iterations) {
		return new Argon2Parameters.Builder(ARGON2_ALGORITHM_TYPE)
			.withVersion(ARGON2_VERSION)
			.withSalt(ArrayUtil.concat(salt, associatedData)) // BC supports salt+secret+associatedData, Spring only salt; squeeze them into salt
			.withParallelism(parallelism)
			.withMemoryAsKB(memory)
			.withIterations(iterations)
			.build();
	}
}
