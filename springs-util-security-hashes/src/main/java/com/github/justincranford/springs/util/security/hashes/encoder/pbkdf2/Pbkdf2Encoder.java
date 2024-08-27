package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
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
    private static record Pbkdf2ClearParameters(byte[] context, byte[] salt, int iterations, int dkLenBytes, String alg) implements ClearParameters { }
    private static record Pbkdf2SecretParameters(byte[] context, CharSequence rawInput) implements SecretParameters { }
    private static record Pbkdf2ClearParametersAndClearHash(Pbkdf2ClearParameters clearParameters, byte[] clearHash) implements ClearParametersAndClearHash { }
    private static record Pbkdf2EncodeDecodeClearParametersFlags(boolean context, boolean salt, boolean iterations, boolean dkLen, boolean alg) { }
    private static record Pbkdf2EncodingDecoding(Base64Util.EncoderDecoder encoderDecoder, Pbkdf2EncodeDecodeClearParametersFlags flags) { }


	public static final class RandomSaltV1 extends IocEncoder {
		public static final RandomSaltV1 DEFAULT1_MIN = new RandomSaltV1(Default1.ENCODING_DECODING_RANDOM_SALT_MIN_FLAGS, Default1.CONTEXT, Default1.ALG, Default1.RANDOM_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN);
		public static final RandomSaltV1 DEFAULT1_MAX = new RandomSaltV1(Default1.ENCODING_DECODING_RANDOM_SALT_MAX_FLAGS, Default1.CONTEXT, Default1.ALG, Default1.RANDOM_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN);
		public RandomSaltV1(final Pbkdf2EncodingDecoding encodingDecoding, final Pbkdf2Context context, final Pbkdf2Util.ALG alg, final int randomSaltLength, final int iterations, final int dkLenBytes) {
			this.encode = (rawInput) -> {
				final byte[] randomSaltForEncode = SecureRandomUtil.randomBytes(randomSaltLength);
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), randomSaltForEncode, iterations, dkLenBytes, alg.alg());
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodingDecoding, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final byte[] poisonedSaltForMatches = null;
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), poisonedSaltForMatches, iterations, dkLenBytes, alg.alg());
				final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodingDecoding, encodedClearParametersAndClearHash, computedClearParameters);
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> {
				if (encodedClearParametersAndClearHash == null || encodedClearParametersAndClearHash.length() == 0) {
					return Boolean.FALSE;
				}
				final byte[] poisonedSaltForUpgradeEncoding = null; 
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), poisonedSaltForUpgradeEncoding, iterations, dkLenBytes, alg.alg());
				final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodingDecoding, encodedClearParametersAndClearHash, computedClearParameters);
				final Pbkdf2ClearParameters parsedClearParameters = parsedClearParametersAndClearHash.clearParameters();
				final byte[] parsedClearHash = parsedClearParametersAndClearHash.clearHash();
				return Boolean.valueOf(
					(!MessageDigest.isEqual(context.clear(), parsedClearParameters.context()))
					|| (randomSaltLength != parsedClearParameters.salt().length)
					|| (iterations != parsedClearParameters.iterations())
					|| (dkLenBytes != parsedClearHash.length)
					|| (!alg.alg().equals(parsedClearParameters.alg()))
				);
			};
		}
	}

	public static final class DerivedSaltV1 extends IocEncoder {
		public static final DerivedSaltV1 DEFAULT1_MIN = new DerivedSaltV1(Default1.ENCODING_DECODING_DERIVED_SALT_MIN_FLAGS, Default1.CONTEXT, Default1.ALG, Default1.DERIVED_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN, Default1.DERIVED_SALT_MAC);
		public static final DerivedSaltV1 DEFAULT1_MAX = new DerivedSaltV1(Default1.ENCODING_DECODING_DERIVED_SALT_MAX_FLAGS, Default1.CONTEXT, Default1.ALG, Default1.DERIVED_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN, Default1.DERIVED_SALT_MAC);
		public DerivedSaltV1(final Pbkdf2EncodingDecoding encodingDecoding, final Pbkdf2Context context, final Pbkdf2Util.ALG alg, final int derivedSaltLength, final int iterations, final int dkLenBytes, final MacUtil.ALG mac) {
			this.encode = (rawInput) -> {
				final byte[] derivedSaltForEncode = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.secret(), rawInput));
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSaltForEncode, iterations, dkLenBytes, alg.alg());
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodingDecoding, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final byte[] derivedSaltForMatches = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.secret(), rawInput));
				final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSaltForMatches, iterations, dkLenBytes, alg.alg());
				final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodingDecoding, encodedClearParametersAndClearHash, computedClearParameters);
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using derived salt
		}
	}

	public static final class ConstantSaltV1 extends IocEncoder {
		public static final ConstantSaltV1 DEFAULT1_MIN = new ConstantSaltV1(Default1.ENCODING_DECODING_CONSTANT_SALT_MIN_FLAGS, Default1.CONTEXT, Default1.ALG, Default1.CONSTANT_SALT, Default1.ITERATIONS, Default1.DK_LEN);
		public static final ConstantSaltV1 DEFAULT1_MAX = new ConstantSaltV1(Default1.ENCODING_DECODING_CONSTANT_SALT_MAX_FLAGS, Default1.CONTEXT, Default1.ALG, Default1.CONSTANT_SALT, Default1.ITERATIONS, Default1.DK_LEN);
		public ConstantSaltV1(final Pbkdf2EncodingDecoding encodingDecoding, final Pbkdf2Context context, final Pbkdf2Util.ALG alg, final byte[] constantSalt, final int iterations, final int dkLenBytes) {
			final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), constantSalt, iterations, dkLenBytes, alg.alg());
			super.encode = (rawInput) ->  {
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodingDecoding, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			super.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodingDecoding, encodedClearParametersAndClearHash, computedClearParameters);
				final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			super.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using constant salt
		}
	}

	private static byte[] computeClearHash(final Pbkdf2ClearParameters clearParameters, final Pbkdf2SecretParameters secretParameters) {
		try {
			final PBEKeySpec spec = new PBEKeySpec(
				secretParameters.rawInput().toString().toCharArray(),
				ArrayUtil.concat(secretParameters.context(), clearParameters.context(), clearParameters.salt()),
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
			secretParameters.context().toString().getBytes(StandardCharsets.UTF_8)
		);
		final byte[] dataChunks = ArrayUtil.concat(
			ByteUtil.byteArray(clearParameters.salt().length), // length, not the actual value, because this method derives the actual value
			clearParameters.context(),
			ByteUtil.byteArray(clearParameters.iterations()),
			ByteUtil.byteArray(clearParameters.dkLenBytes()),
			clearParameters.alg().getBytes(StandardCharsets.UTF_8)
		);
		return MacUtil.hmac(mac.alg(), key, dataChunks);
	}

    public static String encodeClearParameters(final Pbkdf2EncodingDecoding encodingDecoding, final Pbkdf2ClearParameters defaults) {
		final List<Object> parameters = new ArrayList<>(5);
		if (encodingDecoding.flags().context()) {
			parameters.add(encodingDecoding.encoderDecoder().encodeToString(defaults.context()));
		}
		if (encodingDecoding.flags().salt()) {
			parameters.add(encodingDecoding.encoderDecoder().encodeToString(defaults.salt()));
		}
		if (encodingDecoding.flags().iterations()) {
			parameters.add(Integer.valueOf(defaults.iterations()));
		}
		if (encodingDecoding.flags().dkLen()) {
			parameters.add(Integer.valueOf(defaults.dkLenBytes()));
		}
		if (encodingDecoding.flags().alg()) {
			parameters.add(defaults.alg());
		}
		return StringUtil.toString("", Default1.SEPARATOR_ENCODE_PARAMETERS, "", parameters);
    }

    public static Pbkdf2ClearParameters decodeClearParameters(final Pbkdf2EncodingDecoding encodingDecoding, final String clearEncodedParameters, final Pbkdf2ClearParameters defaults) {
        final String[] parts = clearEncodedParameters.split(Default1.SEPARATOR_DECODE_PARAMETERS);
        int part = 0;
        final byte[]  context    = (encodingDecoding.flags().context())    ? encodingDecoding.encoderDecoder().decodeFromString(parts[part++]) : defaults.context();
		final byte[]  salt       = (encodingDecoding.flags().salt())       ? encodingDecoding.encoderDecoder().decodeFromString(parts[part++]) : defaults.salt();
		final int     iterations = (encodingDecoding.flags().iterations()) ? Integer.parseInt(parts[part++])                                   : defaults.iterations();
		final int     dkLenBytes = (encodingDecoding.flags().dkLen())      ? Integer.parseInt(parts[part++])                                   : defaults.dkLenBytes();
		final String  alg        = (encodingDecoding.flags().alg())        ? parts[part++]                                                     : defaults.alg();
		return new Pbkdf2ClearParameters(context, salt, iterations, dkLenBytes, alg);
    }

    public static String encodeClearParametersAndClearHash(final Pbkdf2EncodingDecoding encodingDecoding, final Pbkdf2ClearParametersAndClearHash clearParametersAndClearHash) {
		final String encodeClearParameters = encodeClearParameters(encodingDecoding, clearParametersAndClearHash.clearParameters());
		final String encodeClearHash = encodeClearHash(encodingDecoding, clearParametersAndClearHash.clearHash());
		if (encodeClearParameters.isEmpty()) {
			return encodeClearHash;
		}
		return encodeClearParameters + Default1.SEPARATOR_ENCODE_HASH +  encodeClearHash;
    }
    public static Pbkdf2ClearParametersAndClearHash decodeClearParametersAndClearHash(final Pbkdf2EncodingDecoding encodingDecoding, final String clearParametersAndClearHash, final Pbkdf2ClearParameters defaults) {
        final String[] parts = clearParametersAndClearHash.split(Default1.SEPARATOR_DECODE_HASH);
        int part = 0;
		return new Pbkdf2ClearParametersAndClearHash(decodeClearParameters(encodingDecoding, (parts.length == 1) ? "" : parts[part++], defaults), decodeClearHash(encodingDecoding, parts[part++]));
    }

    private static String encodeClearHash(final Pbkdf2EncodingDecoding encodingDecoding, final byte[] hash) {
		return encodingDecoding.encoderDecoder().encodeToString(hash);
	}
	private static byte[] decodeClearHash(final Pbkdf2EncodingDecoding encodingDecoding, final String encodedHash) {
		return encodingDecoding.encoderDecoder().decodeFromString(encodedHash);
	}

	private static class Default1 {
		private static final Base64Util.EncoderDecoder ENCODER_DECODER = Base64Util.MIME;

		// always omit clearContext because default is empty, always encode random salt, always align iterations/dkLen/alg with min vs max
		private static final Pbkdf2EncodeDecodeClearParametersFlags ENCODE_DECODE_RANDOM_SALT_MIN_FLAGS   = new Pbkdf2EncodeDecodeClearParametersFlags(false, true,  false, false, false);
		private static final Pbkdf2EncodeDecodeClearParametersFlags ENCODE_DECODE_RANDOM_SALT_MAX_FLAGS   = new Pbkdf2EncodeDecodeClearParametersFlags(false,  true,  true,  true,  true);

		// always omit clearContext because default is empty, optionally encode derived salt, always align iterations/dkLen/alg with min vs max
		private static final Pbkdf2EncodeDecodeClearParametersFlags ENCODE_DECODE_DERIVED_SALT_MIN_FLAGS  = new Pbkdf2EncodeDecodeClearParametersFlags(false, false, false, false, false);
		private static final Pbkdf2EncodeDecodeClearParametersFlags ENCODE_DECODE_DERIVED_SALT_MAX_FLAGS  = new Pbkdf2EncodeDecodeClearParametersFlags(false,  true,  true,  true,  true);

		// always omit clearContext because default is empty, never encode constant salt, always align iterations/dkLen/alg with min vs max
		private static final Pbkdf2EncodeDecodeClearParametersFlags ENCODE_DECODE_CONSTANT_SALT_MIN_FLAGS = new Pbkdf2EncodeDecodeClearParametersFlags(false, false, false, false, false);
		private static final Pbkdf2EncodeDecodeClearParametersFlags ENCODE_DECODE_CONSTANT_SALT_MAX_FLAGS = new Pbkdf2EncodeDecodeClearParametersFlags(false,  false,  true,  true,  true);

		private static final Pbkdf2EncodingDecoding ENCODING_DECODING_RANDOM_SALT_MIN_FLAGS   = new Pbkdf2EncodingDecoding(ENCODER_DECODER, ENCODE_DECODE_RANDOM_SALT_MIN_FLAGS);
		private static final Pbkdf2EncodingDecoding ENCODING_DECODING_RANDOM_SALT_MAX_FLAGS   = new Pbkdf2EncodingDecoding(ENCODER_DECODER, ENCODE_DECODE_RANDOM_SALT_MAX_FLAGS);
		private static final Pbkdf2EncodingDecoding ENCODING_DECODING_DERIVED_SALT_MIN_FLAGS  = new Pbkdf2EncodingDecoding(ENCODER_DECODER, ENCODE_DECODE_DERIVED_SALT_MIN_FLAGS);
		private static final Pbkdf2EncodingDecoding ENCODING_DECODING_DERIVED_SALT_MAX_FLAGS  = new Pbkdf2EncodingDecoding(ENCODER_DECODER, ENCODE_DECODE_DERIVED_SALT_MAX_FLAGS);
		private static final Pbkdf2EncodingDecoding ENCODING_DECODING_CONSTANT_SALT_MIN_FLAGS = new Pbkdf2EncodingDecoding(ENCODER_DECODER, ENCODE_DECODE_CONSTANT_SALT_MIN_FLAGS);
		private static final Pbkdf2EncodingDecoding ENCODING_DECODING_CONSTANT_SALT_MAX_FLAGS = new Pbkdf2EncodingDecoding(ENCODER_DECODER, ENCODE_DECODE_CONSTANT_SALT_MAX_FLAGS);
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
