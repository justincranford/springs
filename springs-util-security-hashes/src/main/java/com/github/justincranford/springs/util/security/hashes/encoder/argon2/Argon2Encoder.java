package com.github.justincranford.springs.util.security.hashes.encoder.argon2;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.BiFunction;
import java.util.function.Function;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.argon2.Argon2EncodingUtils.Argon2Hash;

@SuppressWarnings({"nls"})
public class Argon2Encoder {
	private static final int ARGON2_ALGORITHM_TYPE = Argon2Parameters.ARGON2_id;
	private static final int ARGON2_VERSION = Argon2Parameters.ARGON2_VERSION_13;

	private Argon2Encoder() {
		// do nothing
	}

	public static class RandomSalt extends CustomArgon2Encoder {
		public RandomSalt(int randomSaltLength, byte[] associatedData, int hashLength, int parallelism, int memory, int iterations) {
			super(RandomSalt.class, (rawPassword) -> SecureRandomUtil.randomBytes(randomSaltLength), associatedData, hashLength, parallelism, memory, iterations);
		}
	}
	public static class DerivedSalt extends CustomArgon2Encoder {
		public DerivedSalt(int derivedSaltLength, byte[] associatedData, int hashLength, int parallelism, int memory, int iterations) {
			super(DerivedSalt.class, (rawPassword) -> derivedSalt(rawPassword, associatedData, derivedSaltLength, hashLength, parallelism, memory, iterations), associatedData, hashLength, parallelism, memory, iterations);
		}
	}
	public static class ConstantSalt extends CustomArgon2Encoder {
		public ConstantSalt(byte[] constantSalt, byte[] associatedData, int hashLength, int parallelism, int memory, int iterations) {
			super(ConstantSalt.class, (rawPassword) -> constantSalt, associatedData, hashLength, parallelism, memory, iterations);
		}
	}

	public static class CustomArgon2Encoder extends Argon2PasswordEncoder {
		private final Function<CharSequence, String> encodeFunction;
		private final BiFunction<CharSequence, String, Boolean> matchesFunction;
		private final Function<String, Boolean> upgradeEncodingFunction;
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
				final Argon2Parameters params = params(saltSupplier.apply(""), associatedData, parallelism, memory, iterations);
				this.encodeFunction = (rawPassword) -> {
					final byte[] hash = computeHash(rawPassword, params, hashLength);
					return encodeHash(hash); // omit parameters from output
				};
				this.matchesFunction = (rawPassword, encodedPassword) -> MessageDigest.isEqual(encode(rawPassword).getBytes(StandardCharsets.UTF_8), encodedPassword.getBytes(StandardCharsets.UTF_8));
				this.upgradeEncodingFunction = (encodedPassword) -> Boolean.FALSE; // never upgrade encoding when using constant salt
			} else {
				this.encodeFunction = (rawPassword) -> {
					final Argon2Parameters params = params(saltSupplier.apply(rawPassword), associatedData, parallelism, memory, iterations);
					final byte[] hash = computeHash(rawPassword, params, hashLength);
					return Argon2EncodingUtils.encode(hash, params); // include parameters in output
				};
				this.matchesFunction = (rawPassword, encodedPassword) -> super.matches(rawPassword, encodedPassword);
				if (clazz.equals(DerivedSalt.class)) {
					// derived salt => deterministic hash
					this.upgradeEncodingFunction = (encodedPassword) -> Boolean.FALSE; // never upgrade encoding when using derived salt
				} else if (clazz.equals(RandomSalt.class)) {
					// random salt => non-deterministic hash
					this.upgradeEncodingFunction = (encodedPassword) -> {
						if (encodedPassword == null || encodedPassword.length() == 0) {
							return Boolean.FALSE;
						}
						final Argon2Hash hashAndParameters = Argon2EncodingUtils.decode(encodedPassword); // conditionally upgrade encoding when using random salt
						final byte[] hash = hashAndParameters.getHash();
						final Argon2Parameters parameters = hashAndParameters.getParameters();
						return Boolean.valueOf(hash.length < hashLength || parameters.getLanes() < parallelism || parameters.getMemory() < memory || parameters.getIterations() < iterations);
					};
				} else {
					throw new RuntimeException();
				}
			}
		}

		@Override
		public String encode(final CharSequence rawPassword) {
			return this.encodeFunction.apply(rawPassword);
		}
		@Override
		public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
			return this.matchesFunction.apply(rawPassword, encodedPassword).booleanValue();
		}
		@Override
		public boolean upgradeEncoding(final String encodedPassword) {
			return this.upgradeEncodingFunction.apply(encodedPassword).booleanValue();
		}

		private static byte[] computeHash(final CharSequence rawPassword, final Argon2Parameters parameters, int hashLength) {
			final Argon2BytesGenerator generator = new Argon2BytesGenerator();
			generator.init(parameters);
			final byte[] hash = new byte[hashLength];
			generator.generateBytes(rawPassword.toString().toCharArray(), hash);
			return hash;
		}

		private static String encodeHash(final byte[] hash) {
			return Base64Util.STD_ENCODE.string(hash);
		}
	}

	public static byte[] derivedSalt(
		final CharSequence rawPassword,
		final byte[] associatedData,
		final int derivedSaltLength,
		final int hashLength,
		final int parallelism,
		final int memory,
		final int iterations
	) {
		final byte[] bytes = canonicalEncodeDerivedSaltParameters(rawPassword, derivedSaltLength, associatedData, hashLength, parallelism, memory, iterations);
		try {
			return MessageDigest.getInstance("SHA-512").digest(bytes);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
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

	private static Argon2Parameters params(final byte[] salt, final byte[] associatedData, int parallelism, int memory, int iterations) {
		return new Argon2Parameters.Builder(ARGON2_ALGORITHM_TYPE)
			.withVersion(ARGON2_VERSION)
			.withSalt(ArrayUtil.concat(salt, associatedData)) // BC supports salt+secret+associatedData, Spring only salt; squeeze them into salt
			.withParallelism(parallelism)
			.withMemoryAsKB(memory)
			.withIterations(iterations)
			.build();
	}
}
