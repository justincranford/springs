package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.List;
import java.util.function.BiFunction;
import java.util.function.Function;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.ByteUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ClearParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ClearParametersAndClearHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Context;
import com.github.justincranford.springs.util.security.hashes.encoder.model.SecretParameters;
import com.github.justincranford.springs.util.security.hashes.util.MacUtil;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls", "hiding"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2Encoder {
	private static record Pbkdf2Context(byte[] clear, byte[] secret) implements Context { }
    private static record Pbkdf2ClearParameters(byte[] clearContext, byte[] salt, int iterations, int dkLenBytes, String alg) implements ClearParameters { }
    private static record Pbkdf2SecretParameters(byte[] secretContext, CharSequence rawInput) implements SecretParameters { }
    private static record Pbkdf2ClearParametersAndClearHash(Pbkdf2ClearParameters clearParameters, byte[] clearHash) implements ClearParametersAndClearHash { }

	public static final class RandomSalt extends FlexiblePbkdf2Encoder {
		public static final RandomSalt DEFAULT1 = new RandomSalt(Default1.ENCODER_DECODER, Default1.CONTEXT, Default1.ALG, Default1.RANDOM_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN);
		public RandomSalt(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2Context context, final Pbkdf2Encoder.ALG alg, final int randomSaltLength, final int iterations, final int dkLenBytes) {
			super(RandomSalt.class, encoderDecoder, context, alg, (rawInput) -> SecureRandomUtil.randomBytes(randomSaltLength), iterations, dkLenBytes);
		}
	}
	public static final class DerivedSalt extends FlexiblePbkdf2Encoder {
		public static final DerivedSalt DEFAULT1 = new DerivedSalt(Default1.ENCODER_DECODER, Default1.CONTEXT, Default1.ALG, Default1.DERIVED_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN, Default1.DERIVED_SALT_MAC);
		public DerivedSalt(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2Context context, final Pbkdf2Encoder.ALG alg, final int derivedSaltLength, final int iterations, final int dkLenBytes, final MacUtil.ALG mac) {
			super(DerivedSalt.class, encoderDecoder, context, alg, (rawInput) -> derivedSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.secret(), rawInput)), iterations, dkLenBytes);
		}
	}
	public static final class ConstantSalt extends FlexiblePbkdf2Encoder {
		public static final ConstantSalt DEFAULT1 = new ConstantSalt(Default1.ENCODER_DECODER, Default1.CONTEXT, Default1.ALG, Default1.CONSTANT_SALT, Default1.ITERATIONS, Default1.DK_LEN);
		public ConstantSalt(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2Context context, final Pbkdf2Encoder.ALG alg, final byte[] constantSalt, final int iterations, final int dkLenBytes) {
			super(ConstantSalt.class, encoderDecoder, context, alg, (rawInput) -> constantSalt, iterations, dkLenBytes);
		}
	}

	private static abstract class FlexiblePbkdf2Encoder implements PasswordEncoder {
		private final Function<CharSequence, String> encode;
		private final BiFunction<CharSequence, String, Boolean> matches;
		private final Function<String, Boolean> upgradeEncoding;
		public FlexiblePbkdf2Encoder(
			final Class<? extends FlexiblePbkdf2Encoder> clazz,
			final Base64Util.EncoderDecoder encoderDecoder,
			final Pbkdf2Context context,
			final Pbkdf2Encoder.ALG alg,
			final Function<CharSequence, byte[]> saltSupplier,
			final int iterations,
			final int dkLenBytes
		) {
			final BiFunction<Pbkdf2ClearParameters, CharSequence, byte[]> computeClearHash = (clearParameters, rawInput) -> computeClearHash(clearParameters, new Pbkdf2SecretParameters(context.secret(), rawInput));
			final Pbkdf2ClearParameters configuredClearParameters = new Pbkdf2ClearParameters(context.clear(), saltSupplier.apply(""), iterations, dkLenBytes, alg.name());
			if (clazz.equals(ConstantSalt.class) || clazz.equals(DerivedSalt.class)) {
				this.encode = (rawInput) ->  encodeClearHash(encoderDecoder, computeClearHash.apply(configuredClearParameters, rawInput)); // omit  clear parameters
				this.matches = (rawInput, encodedClearHash) -> Boolean.valueOf(MessageDigest.isEqual(decodeClearHash(encoderDecoder, encodedClearHash), computeClearHash.apply(configuredClearParameters, rawInput)));
				this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using constant salt
			} else if (clazz.equals(RandomSalt.class)) {
				this.encode = (rawInput) -> {
					final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), saltSupplier.apply(rawInput), iterations, dkLenBytes, alg.name());
					return encodeClearParametersAndClearHash(encoderDecoder, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computeClearHash.apply(computedClearParameters, rawInput))); // include clear parameters
				};
				this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
					final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encoderDecoder, encodedClearParametersAndClearHash);
					final byte[] computedClearHashChallenge = computeClearHash.apply(parsedClearParametersAndClearHash.clearParameters(), rawInput);
					return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
				};
				this.upgradeEncoding = (encodedClearParametersAndClearHash) -> {
					if (encodedClearParametersAndClearHash == null || encodedClearParametersAndClearHash.length() == 0) {
						return Boolean.FALSE;
					}
					final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encoderDecoder, encodedClearParametersAndClearHash);
					final Pbkdf2ClearParameters parsedClearParameters = parsedClearParametersAndClearHash.clearParameters();
					final byte[] parsedClearHash = parsedClearParametersAndClearHash.clearHash();
					return Boolean.valueOf(
						(!MessageDigest.isEqual(configuredClearParameters.clearContext(), parsedClearParameters.clearContext()))
						|| (configuredClearParameters.salt().length != parsedClearParameters.salt().length)
						|| (configuredClearParameters.iterations() != parsedClearParameters.iterations())
						|| (configuredClearParameters.dkLenBytes() != parsedClearHash.length)
						|| (!configuredClearParameters.alg().equals(parsedClearParameters.alg()))
					);
				};
			} else {
				throw new RuntimeException("Unsupported class " + clazz.getCanonicalName());
			}
		}

		@Override
		public String encode(final CharSequence rawInput) {
			return this.encode.apply(rawInput);
		}
		@Override
		public boolean matches(final CharSequence rawInput, final String encodedClearParametersAndClearHash) {
			return this.matches.apply(rawInput, encodedClearParametersAndClearHash).booleanValue();
		}
		@Override
		public boolean upgradeEncoding(final String encodedClearParametersAndClearHash) {
			return this.upgradeEncoding.apply(encodedClearParametersAndClearHash).booleanValue();
		}
	}

	private static byte[] computeClearHash(final Pbkdf2ClearParameters clearParameters, final Pbkdf2SecretParameters secretParameters) {
		try {
			final PBEKeySpec spec = new PBEKeySpec(
				secretParameters.rawInput().toString().toCharArray(),
				ArrayUtil.concat(secretParameters.secretContext(), clearParameters.clearContext(), clearParameters.salt()),
				clearParameters.iterations(),
				clearParameters.dkLenBytes() * 8
			);
			final SecretKeyFactory skf = SecretKeyFactory.getInstance(clearParameters.alg());
			return skf.generateSecret(spec).getEncoded();
		} catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not create hash", ex);
		}
	}

    public static byte[] derivedSalt(final MacUtil.ALG mac, final Pbkdf2ClearParameters clearParameters, final Pbkdf2SecretParameters secretParameters) {
		final byte[] key = ArrayUtil.concat(
			secretParameters.rawInput().toString().getBytes(StandardCharsets.UTF_8),
			secretParameters.secretContext().toString().getBytes(StandardCharsets.UTF_8)
		);
		final byte[] dataChunks = ArrayUtil.concat(
			ByteUtil.byteArray(clearParameters.salt().length),
			clearParameters.clearContext(),
			ByteUtil.byteArray(clearParameters.iterations()),
			ByteUtil.byteArray(clearParameters.dkLenBytes()),
			clearParameters.alg().getBytes(StandardCharsets.UTF_8)
		);
		return MacUtil.hmac(mac.alg(), key, dataChunks);
	}

    public enum ALG {
		PBKDF2WithHmacSHA1("PBKDF2withHMACSHA1", 20),
		PBKDF2WithHmacSHA384("PBKDF2withHMACSHA224", 28),
		PBKDF2WithHmacSHA224("PBKDF2withHMACSHA256", 32),
		PBKDF2WithHmacSHA512("PBKDF2withHMACSHA384", 48),
		PBKDF2WithHmacSHA256("PBKDF2withHMACSHA512", 64),
		PBKDF2WithHmacSHA512_224("PBKDF2withHMACSHA512/224", 28),
		PBKDF2WithHmacSHA512_256("PBKDF2withHMACSHA512/256", 32),
		PBKDF2WithHmacSHA3_224("PBKDF2withHMACSHA3_256", 28),
		PBKDF2WithHmacSHA3_384("PBKDF2withHMACSHA3_224", 32),
		PBKDF2WithHmacSHA3_256("PBKDF2withHMACSHA3_512", 48),
		PBKDF2WithHmacSHA3_512("PBKDF2withHMACSHA3_384", 64);
		private final String alg;
		private final int lenBytes;
		private ALG(final String alg, final int lenBytes) {
			this.alg = alg;
			this.lenBytes = lenBytes;
		}
		public String alg() {
			return this.alg;
		}
		public int lengthBytes() {
			return this.lenBytes;
		}
	}

	private static class Default1 {
		private static final Base64Util.EncoderDecoder ENCODER_DECODER = Base64Util.MIME;
		private static final Pbkdf2Context CONTEXT = new Pbkdf2Context(new byte[0], new byte[0]);
		private static final ALG ALG = Pbkdf2Encoder.ALG.PBKDF2WithHmacSHA256;
		private static final int RANDOM_SALT_LENGTH = 32;
		private static final int DERIVED_SALT_LENGTH = 32;
		private static final byte[] CONSTANT_SALT = "salt".getBytes(StandardCharsets.UTF_8);
		private static final int ITERATIONS = 600_000;
		private static final int DK_LEN = 32;
		private static final MacUtil.ALG DERIVED_SALT_MAC = MacUtil.ALG.HmacSHA256;
		private static final String SEPARATOR_ENCODE_PARAMETERS = ":";
		private static final String SEPARATOR_DECODE_PARAMETERS = SEPARATOR_ENCODE_PARAMETERS;
	    private static final String SEPARATOR_ENCODE_HASH = "|";
	    private static final String SEPARATOR_DECODE_HASH = "\\" + SEPARATOR_ENCODE_HASH;
	}

    public static String encodeParameters(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2ClearParameters clearParameters) {
		return StringUtil.toString("", Default1.SEPARATOR_ENCODE_PARAMETERS, "",
			List.of(
				encoderDecoder.encodeToString(clearParameters.clearContext()),
				encoderDecoder.encodeToString(clearParameters.salt()),
				Integer.valueOf(clearParameters.iterations()),
				Integer.valueOf(clearParameters.dkLenBytes()),
				clearParameters.alg()
			)
		);
    }

    public static Pbkdf2ClearParameters decodeClearParameters(final Base64Util.EncoderDecoder encoderDecoder, final String clearEncodedParameters) {
        final String[] parts = clearEncodedParameters.split(Default1.SEPARATOR_DECODE_PARAMETERS);
        int part = 0;
        return new Pbkdf2ClearParameters(encoderDecoder.decodeFromString(parts[part++]), encoderDecoder.decodeFromString(parts[part++]), Integer.parseInt(parts[part++]), Integer.parseInt(parts[part++]), parts[part++]);
    }

    public static String encodeClearParametersAndClearHash(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2ClearParametersAndClearHash clearParametersAndClearHash) {
		return encodeParameters(encoderDecoder, clearParametersAndClearHash.clearParameters()) + Default1.SEPARATOR_ENCODE_HASH +  encodeClearHash(encoderDecoder, clearParametersAndClearHash.clearHash());
    }
    public static Pbkdf2ClearParametersAndClearHash decodeClearParametersAndClearHash(final Base64Util.EncoderDecoder encoderDecoder, final String clearParametersAndClearHash) {
        final String[] parts = clearParametersAndClearHash.split(Default1.SEPARATOR_DECODE_HASH);
        return new Pbkdf2ClearParametersAndClearHash(decodeClearParameters(encoderDecoder, parts[0]), decodeClearHash(encoderDecoder, parts[1]));
    }

    private static String encodeClearHash(final Base64Util.EncoderDecoder encoderDecoder, final byte[] hash) {
		return encoderDecoder.encodeToString(hash);
	}
	private static byte[] decodeClearHash(final Base64Util.EncoderDecoder encoderDecoder, final String encodedHash) {
		return encoderDecoder.decodeFromString(encodedHash);
	}
}
