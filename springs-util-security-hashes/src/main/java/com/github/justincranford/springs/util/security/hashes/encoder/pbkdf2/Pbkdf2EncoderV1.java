package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.ByteUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ClearParameters;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ClearParametersAndClearHash;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Context;
import com.github.justincranford.springs.util.security.hashes.encoder.model.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.EncodeDecodeFlags;
import com.github.justincranford.springs.util.security.hashes.encoder.model.EncodeDecodeSeparators;
import com.github.justincranford.springs.util.security.hashes.encoder.model.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.SecretParameters;
import com.github.justincranford.springs.util.security.hashes.util.MacUtil;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.Null;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2EncoderV1 {
	private static record Pbkdf2Context(@Null SecretKey key, @NotNull byte[] secret, @NotNull byte[] clear) implements Context { }
    private static record Pbkdf2ClearParameters(@Null byte[] context, @NotEmpty byte[] salt, @Min(Constraint.MIN_ITERATIONS) int iterations, @Min(Constraint.MIN_DK_BYTES_LENGTH) int dkLenBytes, @NotEmpty String alg) implements ClearParameters { }
    private static record Pbkdf2SecretParameters(@Null SecretKey key, @Null byte[] context, @NotEmpty CharSequence rawInput) implements SecretParameters { }
    private static record Pbkdf2ClearParametersAndClearHash(@NotNull Pbkdf2ClearParameters clearParameters, @NotEmpty byte[] clearHash) implements ClearParametersAndClearHash { }
    private static record Pbkdf2EncodeDecodeSeparators(@NotEmpty String encodeParameters, @NotEmpty String decodeParameters, @NotEmpty String encodeHash, @NotEmpty String decodeHash) implements EncodeDecodeSeparators { }
    private static record Pbkdf2EncodeDecodeFlags(boolean context, boolean salt, boolean iterations, boolean dkLen, boolean alg) implements EncodeDecodeFlags { }
    private static record Pbkdf2EncodeDecode(@NotNull Base64Util.EncoderDecoder encoderDecoder, @NotNull Pbkdf2EncodeDecodeSeparators separators, @NotNull Pbkdf2EncodeDecodeFlags flags) implements EncodeDecode { }

	public static final class RandomSalt extends IocEncoder {
		public static final RandomSalt DEFAULT_KEYLESS_SALT                = new RandomSalt(Default.RANDOM_SALT_ENCODE_SALT,                Default.KEYLESS,         Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public static final RandomSalt DEFAULT_KEYLESS_CONTEXT_SALT        = new RandomSalt(Default.RANDOM_SALT_ENCODE_CONTEXT_SALT,        Default.KEYLESS_CONTEXT, Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public static final RandomSalt DEFAULT_KEYLESS_SALT_OTHERS         = new RandomSalt(Default.RANDOM_SALT_ENCODE_SALT_OTHERS,         Default.KEYLESS,         Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public static final RandomSalt DEFAULT_KEYLESS_CONTEXT_SALT_OTHERS = new RandomSalt(Default.RANDOM_SALT_ENCODE_CONTEXT_SALT_OTHERS, Default.KEYLESS_CONTEXT, Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public static final RandomSalt DEFAULT_KEYED_SALT                  = new RandomSalt(Default.RANDOM_SALT_ENCODE_SALT,                Default.KEYED,           Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public static final RandomSalt DEFAULT_KEYED_CONTEXT_SALT          = new RandomSalt(Default.RANDOM_SALT_ENCODE_CONTEXT_SALT,        Default.KEYED_CONTEXT,   Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public static final RandomSalt DEFAULT_KEYED_SALT_OTHERS           = new RandomSalt(Default.RANDOM_SALT_ENCODE_SALT_OTHERS,         Default.KEYED,           Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public static final RandomSalt DEFAULT_KEYED_CONTEXT_SALT_OTHERS   = new RandomSalt(Default.RANDOM_SALT_ENCODE_CONTEXT_SALT_OTHERS, Default.KEYED_CONTEXT,   Default.ALG, Default.RANDOM_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN);
		public RandomSalt(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2Context context, @NotNull final Pbkdf2Util.ALG alg, @Min(Constraint.MIN_RANDOM_SALT_BYTES_LENGTH) final int randomSaltLength, @Min(Constraint.MIN_ITERATIONS) final int iterations, @Min(Constraint.MIN_DK_BYTES_LENGTH) final int dkLenBytes) {
			this.encode = (rawInput) -> {
				final byte[] randomSaltForEncode = SecureRandomUtil.randomBytes(randomSaltLength);
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), randomSaltForEncode, iterations, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodeDecode, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final byte[] poisonedSaltForMatches = null;
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), poisonedSaltForMatches, iterations, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> {
				if (encodedClearParametersAndClearHash == null || encodedClearParametersAndClearHash.length() == 0) {
					return Boolean.FALSE;
				}
				final byte[] poisonedSaltForUpgradeEncoding = null; 
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), poisonedSaltForUpgradeEncoding, iterations, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				@NotNull final Pbkdf2ClearParameters parsedClearParameters = parsedClearParametersAndClearHash.clearParameters();
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

	public static final class DerivedSalt extends IocEncoder {
		public static final DerivedSalt DEFAULT_KEYLESS                     = new DerivedSalt(Default.DERIVED_SALT_ENCODE_NONE,                Default.KEYLESS,         Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYLESS_CONTEXT             = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT,             Default.KEYLESS_CONTEXT, Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYLESS_OTHERS              = new DerivedSalt(Default.DERIVED_SALT_ENCODE_OTHERS,              Default.KEYLESS,         Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYLESS_CONTEXT_OTHERS      = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT_OTHERS,      Default.KEYLESS_CONTEXT, Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYLESS_SALT                = new DerivedSalt(Default.DERIVED_SALT_ENCODE_SALT,                Default.KEYLESS,         Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYLESS_CONTEXT_SALT        = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT_SALT,        Default.KEYLESS_CONTEXT, Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYLESS_SALT_OTHERS         = new DerivedSalt(Default.DERIVED_SALT_ENCODE_SALT_OTHERS,         Default.KEYLESS,         Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYLESS_CONTEXT_SALT_OTHERS = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT_SALT_OTHERS, Default.KEYLESS_CONTEXT, Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED                       = new DerivedSalt(Default.DERIVED_SALT_ENCODE_NONE,                Default.KEYED,           Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED_CONTEXT               = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT,             Default.KEYED_CONTEXT,   Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED_OTHERS                = new DerivedSalt(Default.DERIVED_SALT_ENCODE_OTHERS,              Default.KEYED,           Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED_CONTEXT_OTHERS        = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT_OTHERS,      Default.KEYED_CONTEXT,   Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED_SALT                  = new DerivedSalt(Default.DERIVED_SALT_ENCODE_SALT,                Default.KEYED,           Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED_CONTEXT_SALT          = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT_SALT,        Default.KEYED_CONTEXT,   Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED_SALT_OTHERS           = new DerivedSalt(Default.DERIVED_SALT_ENCODE_SALT_OTHERS,         Default.KEYED,           Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public static final DerivedSalt DEFAULT_KEYED_CONTEXT_SALT_OTHERS   = new DerivedSalt(Default.DERIVED_SALT_ENCODE_CONTEXT_SALT_OTHERS, Default.KEYED_CONTEXT,   Default.ALG, Default.DERIVED_SALT_LENGTH, Default.ITERATIONS, Default.DK_LEN, Default.DERIVE_ALG);
		public DerivedSalt(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2Context context, @NotNull final Pbkdf2Util.ALG alg, @Min(Constraint.MIN_DERIVED_SALT_BYTES_LENGTH) final int derivedSaltLength, @Min(Constraint.MIN_ITERATIONS) final int iterations, @Min(Constraint.MIN_DK_BYTES_LENGTH) final int dkLenBytes, @NotNull final MacUtil.ALG mac) {
			this.encode = (rawInput) -> {
				final byte[] derivedSaltForEncode = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput));
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSaltForEncode, iterations, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodeDecode, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final byte[] derivedSaltForMatches = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput));
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSaltForMatches, iterations, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using derived salt
		}
	}

	public static final class ConstantSalt extends IocEncoder {
		public static final ConstantSalt DEFAULT_KEYLESS                     = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_NONE,                Default.KEYLESS,         Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYLESS_CONTEXT             = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT,             Default.KEYLESS_CONTEXT, Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYLESS_OTHERS              = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_OTHERS,              Default.KEYLESS,         Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYLESS_CONTEXT_OTHERS      = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT_OTHERS,      Default.KEYLESS_CONTEXT, Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYLESS_SALT                = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_SALT,                Default.KEYLESS,         Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYLESS_CONTEXT_SALT        = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT_SALT,        Default.KEYLESS_CONTEXT, Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYLESS_SALT_OTHERS         = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_SALT_OTHERS,         Default.KEYLESS,         Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYLESS_CONTEXT_SALT_OTHERS = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT_SALT_OTHERS, Default.KEYLESS_CONTEXT, Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED                       = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_NONE,                Default.KEYED,           Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED_CONTEXT               = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT,             Default.KEYED_CONTEXT,   Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED_OTHERS                = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_OTHERS,              Default.KEYED,           Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED_CONTEXT_OTHERS        = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT_OTHERS,      Default.KEYED_CONTEXT,   Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED_SALT                  = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_SALT,                Default.KEYED,           Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED_CONTEXT_SALT          = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT_SALT,        Default.KEYED_CONTEXT,   Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED_SALT_OTHERS           = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_SALT_OTHERS,         Default.KEYED,           Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public static final ConstantSalt DEFAULT_KEYED_CONTEXT_SALT_OTHERS   = new ConstantSalt(Default.CONSTANT_SALT_ENCODE_CONTEXT_SALT_OTHERS, Default.KEYED_CONTEXT,   Default.ALG, Default.CONSTANT_SALT, Default.ITERATIONS, Default.DK_LEN);
		public ConstantSalt(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2Context context, @NotNull final Pbkdf2Util.ALG alg, @NotEmpty final byte[] constantSalt, @Min(Constraint.MIN_ITERATIONS) final int iterations, @Min(Constraint.MIN_DK_BYTES_LENGTH) final int dkLenBytes) {
			@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), constantSalt, iterations, dkLenBytes, alg.alg());
			super.encode = (rawInput) ->  {
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodeDecode, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			super.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				@NotNull final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			super.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using constant salt
		}
	}

	private static byte[] computeClearHash(@NotNull final Pbkdf2ClearParameters clearParameters, @NotNull final Pbkdf2SecretParameters secretParameters) {
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

    public static byte[] deriveSalt(@NotNull final MacUtil.ALG mac, @NotNull final Pbkdf2ClearParameters clearParameters, @NotNull final Pbkdf2SecretParameters secretParameters) {
    	return (secretParameters.key() == null)
			? deriveSaltWithConstructedHmacKey(mac, clearParameters, secretParameters)
			: derivedSaltWithInputHmacKey(mac, clearParameters, secretParameters);
	}

	private static byte[] deriveSaltWithConstructedHmacKey(@NotNull final MacUtil.ALG mac, @NotNull final Pbkdf2ClearParameters clearParameters, @NotNull final Pbkdf2SecretParameters secretParameters) {
		final byte[] keyBytes = ArrayUtil.concat(
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
		return MacUtil.hmac(mac.alg(), new SecretKeySpec(keyBytes, clearParameters.alg()), dataChunks);
	}

	private static byte[] derivedSaltWithInputHmacKey(@NotNull final MacUtil.ALG mac, @NotNull final Pbkdf2ClearParameters clearParameters, @NotNull final Pbkdf2SecretParameters secretParameters) {
		final byte[] dataChunks = ArrayUtil.concat(
			secretParameters.rawInput().toString().getBytes(StandardCharsets.UTF_8),
			secretParameters.context().toString().getBytes(StandardCharsets.UTF_8),
			ByteUtil.byteArray(clearParameters.salt().length), // length, not the actual value, because this method derives the actual value
			clearParameters.context(),
			ByteUtil.byteArray(clearParameters.iterations()),
			ByteUtil.byteArray(clearParameters.dkLenBytes()),
			clearParameters.alg().getBytes(StandardCharsets.UTF_8)
		);
		return MacUtil.hmac(mac.alg(), secretParameters.key(), dataChunks);
	}

    public static String encodeClearParameters(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2ClearParameters defaults) {
		final List<Object> parameters = new ArrayList<>(5);
		if (encodeDecode.flags().context()) {
			parameters.add(encodeDecode.encoderDecoder().encodeToString(defaults.context()));
		}
		if (encodeDecode.flags().salt()) {
			parameters.add(encodeDecode.encoderDecoder().encodeToString(defaults.salt()));
		}
		if (encodeDecode.flags().iterations()) {
			parameters.add(Integer.valueOf(defaults.iterations()));
		}
		if (encodeDecode.flags().dkLen()) {
			parameters.add(Integer.valueOf(defaults.dkLenBytes()));
		}
		if (encodeDecode.flags().alg()) {
			parameters.add(defaults.alg());
		}
		return StringUtil.toString("", encodeDecode.separators().encodeParameters(), "", parameters);
    }

    public static Pbkdf2ClearParameters decodeClearParameters(@NotNull final Pbkdf2EncodeDecode encodeDecode, final String clearEncodedParameters, @NotNull final Pbkdf2ClearParameters defaults) {
        final String[] parts = clearEncodedParameters.split(encodeDecode.separators().decodeParameters());
        int part = 0;
        final byte[]  context    = (encodeDecode.flags().context())    ? encodeDecode.encoderDecoder().decodeFromString(parts[part++]) : defaults.context();
		final byte[]  salt       = (encodeDecode.flags().salt())       ? encodeDecode.encoderDecoder().decodeFromString(parts[part++]) : defaults.salt();
		final int     iterations = (encodeDecode.flags().iterations()) ? Integer.parseInt(parts[part++])                               : defaults.iterations();
		final int     dkLenBytes = (encodeDecode.flags().dkLen())      ? Integer.parseInt(parts[part++])                               : defaults.dkLenBytes();
		final String  alg        = (encodeDecode.flags().alg())        ? parts[part++]                                                 : defaults.alg();
		return new Pbkdf2ClearParameters(context, salt, iterations, dkLenBytes, alg);
    }

    public static String encodeClearParametersAndClearHash(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2ClearParametersAndClearHash clearParametersAndClearHash) {
		final String encodeClearParameters = encodeClearParameters(encodeDecode, clearParametersAndClearHash.clearParameters());
		final String encodeClearHash = encodeClearHash(encodeDecode, clearParametersAndClearHash.clearHash());
		if (encodeClearParameters.isEmpty()) {
			return encodeClearHash;
		}
		return encodeClearParameters + encodeDecode.separators().encodeHash() +  encodeClearHash;
    }
    public static Pbkdf2ClearParametersAndClearHash decodeClearParametersAndClearHash(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final String clearParametersAndClearHash, @NotNull final Pbkdf2ClearParameters defaults) {
        final String[] parts = clearParametersAndClearHash.split(encodeDecode.separators().decodeHash());
        int part = 0;
		return new Pbkdf2ClearParametersAndClearHash(decodeClearParameters(encodeDecode, (parts.length == 1) ? "" : parts[part++], defaults), decodeClearHash(encodeDecode, parts[part++]));
    }

    private static String encodeClearHash(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotEmpty final byte[] hash) {
		return encodeDecode.encoderDecoder().encodeToString(hash);
	}
	private static byte[] decodeClearHash(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotEmpty final String encodedHash) {
		return encodeDecode.encoderDecoder().decodeFromString(encodedHash);
	}

	private static class Constraint {
		private static final int MIN_RANDOM_SALT_BYTES_LENGTH = 8;
		private static final int MIN_DERIVED_SALT_BYTES_LENGTH = 8;
		private static final int MIN_ITERATIONS = 1;
		private static final int MIN_DK_BYTES_LENGTH = 16;
	}

	private static class Default {
		private static final Pbkdf2Util.ALG ALG = Pbkdf2Util.ALG.PBKDF2WithHmacSHA256;
		private static final MacUtil.ALG DERIVE_ALG = MacUtil.ALG.HmacSHA256;
		private static final int RANDOM_SALT_LENGTH = 32;
		private static final int DERIVED_SALT_LENGTH = 32;
		private static final byte[] CONSTANT_SALT = "salt".getBytes(StandardCharsets.UTF_8);
		private static final int ITERATIONS = 600_000;
		private static final int DK_LEN = 32;
		private static final SecretKey DERIVE_KEY = new SecretKeySpec("hmacsecretkeybytesvariablelength".getBytes(StandardCharsets.UTF_8), ALG.alg());
		private static final Pbkdf2Context KEYLESS         = new Pbkdf2Context(null, new byte[0], new byte[0]);
		private static final Pbkdf2Context KEYLESS_CONTEXT = new Pbkdf2Context(null, new byte[23], new byte[13]);
		private static final Pbkdf2Context KEYED           = new Pbkdf2Context(DERIVE_KEY, new byte[0], new byte[0]);
		private static final Pbkdf2Context KEYED_CONTEXT   = new Pbkdf2Context(DERIVE_KEY, new byte[23], new byte[13]);

	    private static final Base64Util.EncoderDecoder ENCODER_DECODER = Base64Util.MIME;
		private static final String ENCODE_SEPARATOR_PARAMETERS = ":";
		private static final String DECODE_SEPARATOR_PARAMETERS = ENCODE_SEPARATOR_PARAMETERS;
	    private static final String ENCODE_SEPARATOR_HASH = "|";
	    private static final String DECODE_SEPARATOR_HASH = "\\" + ENCODE_SEPARATOR_HASH;
	    private static final Pbkdf2EncodeDecodeSeparators SEPARATORS = new Pbkdf2EncodeDecodeSeparators(ENCODE_SEPARATOR_PARAMETERS, DECODE_SEPARATOR_PARAMETERS, ENCODE_SEPARATOR_HASH, DECODE_SEPARATOR_HASH);

		private static final Pbkdf2EncodeDecodeFlags FLAGS_NONE                = new Pbkdf2EncodeDecodeFlags(false, false,  false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FLAGS_CONTEXT             = new Pbkdf2EncodeDecodeFlags(true,  false,  false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FLAGS_SALT                = new Pbkdf2EncodeDecodeFlags(false, true,   false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FLAGS_OTHERS              = new Pbkdf2EncodeDecodeFlags(false, false,  true,  true,  true);
		private static final Pbkdf2EncodeDecodeFlags FLAGS_CONTEXT_SALT        = new Pbkdf2EncodeDecodeFlags(true,  true,   false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FLAGS_CONTEXT_OTHERS      = new Pbkdf2EncodeDecodeFlags(true,  false,  true,  true,  true);
		private static final Pbkdf2EncodeDecodeFlags FLAGS_SALT_OTHERS         = new Pbkdf2EncodeDecodeFlags(false, true,   true,  true,  true);
		private static final Pbkdf2EncodeDecodeFlags FLAGS_CONTEXT_SALT_OTHERS = new Pbkdf2EncodeDecodeFlags(true,  true,   true,  true,  true);

		// RandomSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final Pbkdf2EncodeDecode      RANDOM_SALT_ENCODE_SALT                  = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_SALT);
		private static final Pbkdf2EncodeDecode      RANDOM_SALT_ENCODE_CONTEXT_SALT          = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_SALT);
		private static final Pbkdf2EncodeDecode      RANDOM_SALT_ENCODE_SALT_OTHERS           = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_SALT_OTHERS);
		private static final Pbkdf2EncodeDecode      RANDOM_SALT_ENCODE_CONTEXT_SALT_OTHERS   = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_SALT_OTHERS);

		// DerivedSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_NONE                 = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_NONE);
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_CONTEXT              = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT);
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_SALT                 = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_SALT);
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_OTHERS               = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_OTHERS);
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_CONTEXT_SALT         = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_SALT);
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_CONTEXT_OTHERS       = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_OTHERS);
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_SALT_OTHERS          = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_SALT_OTHERS);
		private static final Pbkdf2EncodeDecode      DERIVED_SALT_ENCODE_CONTEXT_SALT_OTHERS  = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_SALT_OTHERS);

		// ConstantSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_NONE                = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_NONE);
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_CONTEXT             = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT);
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_SALT                = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_SALT);
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_OTHERS              = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_OTHERS);
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_CONTEXT_SALT        = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_SALT);
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_CONTEXT_OTHERS      = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_OTHERS);
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_SALT_OTHERS         = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_SALT_OTHERS);
		private static final Pbkdf2EncodeDecode      CONSTANT_SALT_ENCODE_CONTEXT_SALT_OTHERS = new Pbkdf2EncodeDecode(ENCODER_DECODER, SEPARATORS, FLAGS_CONTEXT_SALT_OTHERS);
	}
}
