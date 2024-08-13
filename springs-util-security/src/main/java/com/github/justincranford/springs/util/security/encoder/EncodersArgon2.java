package com.github.justincranford.springs.util.security.encoder;

import static org.bouncycastle.crypto.params.Argon2Parameters.ARGON2_id;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.function.Function;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.encoder.Argon2EncodingUtils.Argon2Hash;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@SuppressWarnings({"nls"})
public class EncodersArgon2 {
	public static class RandomSalt extends CustomArgon2Encoder {
		public RandomSalt(byte[] context, int randomSaltLength, int hashLength, int parallelism, int memory, int iterations) {
			super(context, (rawPassword) -> SecureRandomUtil.randomBytes(randomSaltLength), hashLength, parallelism, memory, iterations);
		}
	}
	public static class DerivedSalt extends CustomArgon2Encoder {
		public DerivedSalt(byte[] context, int minimumDerivedSaltLength, int hashLength, int parallelism, int memory, int iterations) {
			super(context, (rawPassword) -> derivedSalt(rawPassword, context, minimumDerivedSaltLength, hashLength, parallelism, memory, iterations), hashLength, parallelism, memory, iterations);
		}
	}
	public static class ConstantSalt extends CustomArgon2Encoder {
		public ConstantSalt(byte[] context, byte[] constantSalt, int hashLength, int parallelism, int memory, int iterations) {
			super(context, (rawPassword) -> constantSalt, hashLength, parallelism, memory, iterations);
		}
	}

	private static class CustomArgon2Encoder extends Argon2PasswordEncoder {
		private final Function<CharSequence, String> encodeFunction;
		private final Function<String, Boolean> upgradeEncodingFunction;
		public CustomArgon2Encoder(byte[] context, Function<CharSequence, byte[]> saltSupplier, int hashLength, int parallelism, int memory, int iterations) {
			super(saltSupplier.apply("").length, hashLength, parallelism, memory, iterations);

			final String randomTestPassword = Base64Util.STD_ENCODE.string(SecureRandomUtil.randomBytes(6)); // 8-chars low-ASCII (24-bits entropy from 48-bits/6-bytes randomness)
			if (MessageDigest.isEqual(saltSupplier.apply(randomTestPassword), saltSupplier.apply(randomTestPassword))) {
				// constant salt (i.e. salt is reused for different passwords) => deterministic hash
				final byte[] constantExtendedSalt = ArrayUtil.concat(context, saltSupplier.apply(""));
				final Argon2Parameters constantParametersPerRawPassword = new Argon2Parameters.Builder(ARGON2_id)
					.withSalt(constantExtendedSalt)
					.withParallelism(parallelism)
					.withMemoryAsKB(memory)
					.withIterations(iterations)
					.build();
				this.encodeFunction = (rawPassword) -> {
					final byte[] hash = hash(rawPassword, constantParametersPerRawPassword, hashLength);
					return encodeHash(hash); // omit parameters from output
				};
				this.upgradeEncodingFunction = (encodedPassword) -> Boolean.FALSE; // never upgrade encoding within this encoder instance, but DelegatingPasswordEncoder may trigger it
			} else {
				// random or derived salt (i.e. salt is not reused for different passwords)
				this.encodeFunction = (rawPassword) -> {
					final byte[] uniqueExtendedSalt = ArrayUtil.concat(context, saltSupplier.apply(rawPassword));
					final Argon2Parameters uniqueParametersPerRawPassword = new Argon2Parameters.Builder(ARGON2_id)
						.withSalt(uniqueExtendedSalt)
						.withParallelism(parallelism)
						.withMemoryAsKB(memory)
						.withIterations(iterations)
						.build();
					final byte[] hash = hash(rawPassword, uniqueParametersPerRawPassword, hashLength);
					return Argon2EncodingUtils.encode(hash, uniqueParametersPerRawPassword); // include parameters in output
				};
				if (MessageDigest.isEqual(this.encodeFunction.apply(randomTestPassword).getBytes(), this.encodeFunction.apply(randomTestPassword).getBytes())) {
					// derived salt => deterministic hash
					this.upgradeEncodingFunction = (encodedPassword) -> Boolean.FALSE; // never upgrade encoding within this encoder instance, but DelegatingPasswordEncoder may trigger it
				} else {
					// random salt => non-deterministic hash
					this.upgradeEncodingFunction = (encodedPassword) -> {
						if (encodedPassword == null || encodedPassword.length() == 0) {
							return Boolean.FALSE;
						}
						final Argon2Hash hashAndParameters = Argon2EncodingUtils.decode(encodedPassword); // upgrade encoding if hashLength, parallelism, memory, or iterations are too low
						final byte[] hash = hashAndParameters.getHash();
						final Argon2Parameters parameters = hashAndParameters.getParameters();
						return Boolean.valueOf(hash.length < hashLength || parameters.getLanes() < parallelism || parameters.getMemory() < memory || parameters.getIterations() < iterations);
					};
				}
			}
		}
		@Override
		public String encode(final CharSequence rawPassword) {
			return this.encodeFunction.apply(rawPassword);
		}
		@Override
		public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
			return MessageDigest.isEqual(encode(rawPassword).getBytes(StandardCharsets.UTF_8), encodedPassword.getBytes(StandardCharsets.UTF_8));
		}
		@Override
		public boolean upgradeEncoding(final String encodedPassword) {
			return this.upgradeEncodingFunction.apply(encodedPassword).booleanValue();
		}

		private static byte[] hash(final CharSequence rawPassword, final Argon2Parameters parameters, int hashLength) {
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

	private static byte[] derivedSalt(
		final CharSequence rawPassword,
		byte[] context,
		int minimumDerivedSaltLength,
		int hashLength,
		int parallelism,
		int memory,
		int iterations
	) {
		final MessageDigest messageDigest;
		try {
			messageDigest = MessageDigest.getInstance("SHA-512");
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
		return messageDigest.digest(
			ByteBuffer.allocate(rawPassword.length() + 4 + context.length + 4 + 4 + 4 + 4 + 4)
				.put(rawPassword.toString().getBytes(StandardCharsets.UTF_8))
				.put(context)
				.putInt(minimumDerivedSaltLength)
				.putInt(ARGON2_id)
				.putInt(hashLength)
				.putInt(parallelism)
				.putInt(memory)
				.putInt(iterations)
				.array()
			);
	}
}
