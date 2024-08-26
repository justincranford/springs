package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.ByteUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ClearParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ClearParametersAndClearHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Context;
import com.github.justincranford.springs.util.security.hashes.encoder.model.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.SecretParameters;
import com.github.justincranford.springs.util.security.hashes.util.MacUtil;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2Encoder {
	private static record Pbkdf2Context(byte[] clear, byte[] secret) implements Context { }
    private static record Pbkdf2ClearParameters(byte[] clearContext, byte[] salt, int iterations, int dkLenBytes, String alg) implements ClearParameters { }
    private static record Pbkdf2SecretParameters(byte[] secretContext, CharSequence rawInput) implements SecretParameters { }
    private static record Pbkdf2ClearParametersAndClearHash(Pbkdf2ClearParameters clearParameters, byte[] clearHash) implements ClearParametersAndClearHash { }

	public static final class RandomSalt extends IocEncoder {
		public static final RandomSalt DEFAULT1 = new RandomSalt(Default1.ENCODER_DECODER, Default1.CONTEXT, Default1.ALG, Default1.RANDOM_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN);
		public RandomSalt(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2Context context, final Pbkdf2Util.ALG alg, final int randomSaltLength, final int iterations, final int dkLenBytes) {
			this.encode = (rawInput) -> {
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), SecureRandomUtil.randomBytes(randomSaltLength), iterations, dkLenBytes, alg.alg());
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encoderDecoder, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash)); // include clear parameters
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encoderDecoder, encodedClearParametersAndClearHash);
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
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
					(!MessageDigest.isEqual(context.clear(), parsedClearParameters.clearContext()))
					|| (randomSaltLength != parsedClearParameters.salt().length)
					|| (iterations != parsedClearParameters.iterations())
					|| (dkLenBytes != parsedClearHash.length)
					|| (!alg.alg().equals(parsedClearParameters.alg()))
				);
			};
		}
	}

	public static final class DerivedSalt extends IocEncoder {
		public static final DerivedSalt DEFAULT1 = new DerivedSalt(Default1.ENCODER_DECODER, Default1.CONTEXT, Default1.ALG, Default1.DERIVED_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN, Default1.DERIVED_SALT_MAC);
		public DerivedSalt(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2Context context, final Pbkdf2Util.ALG alg, final int derivedSaltLength, final int iterations, final int dkLenBytes, final MacUtil.ALG mac) {
			this.encode = (rawInput) -> {
				final byte[] derivedSalt = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.secret(), rawInput));
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSalt, iterations, dkLenBytes, alg.alg());
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearHash(encoderDecoder, computedClearHash); // omit clear parameters
			};
			this.matches = (rawInput, encodedClearHash) -> {
				final byte[] parsedClearHash = decodeClearHash(encoderDecoder, encodedClearHash);
				final byte[] derivedSalt = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.secret(), rawInput));
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSalt, iterations, dkLenBytes, alg.alg());
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(computedClearParameters, constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearHash, computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using derived salt
		}
	}

	public static final class ConstantSalt extends IocEncoder {
		public static final ConstantSalt DEFAULT1 = new ConstantSalt(Default1.ENCODER_DECODER, Default1.CONTEXT, Default1.ALG, Default1.CONSTANT_SALT, Default1.ITERATIONS, Default1.DK_LEN);
		public ConstantSalt(final Base64Util.EncoderDecoder encoderDecoder, final Pbkdf2Context context, final Pbkdf2Util.ALG alg, final byte[] constantSalt, final int iterations, final int dkLenBytes) {
			final Pbkdf2ClearParameters constantClearParameters = new Pbkdf2ClearParameters(context.clear(), constantSalt, iterations, dkLenBytes, alg.alg());
			super.encode = (rawInput) ->  {
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(constantClearParameters, constructedSecretParameters);
				return encodeClearHash(encoderDecoder, computedClearHash); // omit  clear parameters
			};
			super.matches = (rawInput, encodedClearHash) -> {
				final byte[] parsedClearHash = decodeClearHash(encoderDecoder, encodedClearHash);
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(constantClearParameters, constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearHash, computedClearHashChallenge));
			};
			super.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using constant salt
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

    public static byte[] deriveSalt(final MacUtil.ALG mac, final Pbkdf2ClearParameters clearParameters, final Pbkdf2SecretParameters secretParameters) {
		final byte[] key = ArrayUtil.concat(
			secretParameters.rawInput().toString().getBytes(StandardCharsets.UTF_8),
			secretParameters.secretContext().toString().getBytes(StandardCharsets.UTF_8)
		);
		final byte[] dataChunks = ArrayUtil.concat(
			ByteUtil.byteArray(clearParameters.salt().length), // length, not the actual value, because this method derives the actual value
			clearParameters.clearContext(),
			ByteUtil.byteArray(clearParameters.iterations()),
			ByteUtil.byteArray(clearParameters.dkLenBytes()),
			clearParameters.alg().getBytes(StandardCharsets.UTF_8)
		);
		return MacUtil.hmac(mac.alg(), key, dataChunks);
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

	private static class Default1 {
		private static final Base64Util.EncoderDecoder ENCODER_DECODER = Base64Util.MIME;
		private static final Pbkdf2Context CONTEXT = new Pbkdf2Context(new byte[0], new byte[0]);
		private static final Pbkdf2Util.ALG ALG = Pbkdf2Util.ALG.PBKDF2WithHmacSHA256;
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
}
