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
    private static record Pbkdf2ClearParameters(@Null byte[] context, @NotEmpty byte[] salt, @Min(C.MIN_ITERATIONS) int iter, @Min(C.MIN_DK_BYTES_LEN) int dkLenBytes, @NotEmpty String alg) implements ClearParameters { }
    private static record Pbkdf2SecretParameters(@Null SecretKey key, @Null byte[] context, @NotEmpty CharSequence rawInput) implements SecretParameters { }
    private static record Pbkdf2ClearParametersAndClearHash(@NotNull Pbkdf2ClearParameters clearParameters, @NotEmpty byte[] clearHash) implements ClearParametersAndClearHash { }
    private static record Pbkdf2EncodeDecodeSeparators(@NotEmpty String encodeParameters, @NotEmpty String decodeParameters, @NotEmpty String encodeHash, @NotEmpty String decodeHash) implements EncodeDecodeSeparators { }
    private static record Pbkdf2EncodeDecodeFlags(boolean context, boolean salt, boolean iter, boolean dkLen, boolean alg) implements EncodeDecodeFlags { }
    private static record Pbkdf2EncodeDecode(@NotNull Base64Util.EncoderDecoder encoderDecoder, @NotNull Pbkdf2EncodeDecodeSeparators separators, @NotNull Pbkdf2EncodeDecodeFlags flags) implements EncodeDecode { }

	public static final class RandomSalt extends IocEncoder {
		public static final RandomSalt DEFAULT_SALT             = new RandomSalt(D.RAND_SALT,         D.NONE,    D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public static final RandomSalt DEFAULT_CTX_SALT         = new RandomSalt(D.RAND_CTX_SALT,     D.CTX,     D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public static final RandomSalt DEFAULT_SALT_OTH         = new RandomSalt(D.RAND_SALT_OTH,     D.NONE,    D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public static final RandomSalt DEFAULT_CTX_SALT_OTH     = new RandomSalt(D.RAND_CTX_SALT_OTH, D.CTX,     D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_SALT         = new RandomSalt(D.RAND_SALT,         D.KEY,     D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_CTX_SALT     = new RandomSalt(D.RAND_CTX_SALT,     D.KEY_CTX, D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_SALT_OTH     = new RandomSalt(D.RAND_SALT_OTH,     D.KEY,     D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_CTX_SALT_OTH = new RandomSalt(D.RAND_CTX_SALT_OTH, D.KEY_CTX, D.PRF_ALG, D.RAND_LEN_BYTES, D.ITER, D.DK_LEN);
		public RandomSalt(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2Context context, @NotNull final Pbkdf2Util.ALG alg, @Min(C.MIN_RAND_BYTES_LEN) final int randomSaltLen, @Min(C.MIN_ITERATIONS) final int iter, @Min(C.MIN_DK_BYTES_LEN) final int dkLenBytes) {
			this.encode = (rawInput) -> {
				final byte[] randomSaltBytesForEncode = SecureRandomUtil.randomBytes(randomSaltLen);
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), randomSaltBytesForEncode, iter, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodeDecode, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final byte[] poisonSaltBytesForMatches = null;
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), poisonSaltBytesForMatches, iter, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> {
				if (encodedClearParametersAndClearHash == null || encodedClearParametersAndClearHash.length() == 0) {
					return Boolean.FALSE;
				}
				final byte[] poisonSaltBytesForUpgradeEncoding = null; 
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), poisonSaltBytesForUpgradeEncoding, iter, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				@NotNull final Pbkdf2ClearParameters parsedClearParameters = parsedClearParametersAndClearHash.clearParameters();
				final byte[] parsedClearHash = parsedClearParametersAndClearHash.clearHash();
				return Boolean.valueOf(
					(!MessageDigest.isEqual(context.clear(), parsedClearParameters.context()))
					|| (randomSaltLen != parsedClearParameters.salt().length)
					|| (iter != parsedClearParameters.iter())
					|| (dkLenBytes != parsedClearHash.length)
					|| (!alg.alg().equals(parsedClearParameters.alg()))
				);
			};
		}
	}

	public static final class DerivedSalt extends IocEncoder {
		public static final DerivedSalt DEFAULT_NONE             = new DerivedSalt(D.DER_NONE,         D.NONE,    D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX              = new DerivedSalt(D.DER_CTX,          D.CTX,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_OTH              = new DerivedSalt(D.DER_OTH,          D.NONE,    D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX_OTH          = new DerivedSalt(D.DER_CTX_OTH,      D.CTX,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_SALT             = new DerivedSalt(D.DER_SALT,         D.NONE,    D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX_SALT         = new DerivedSalt(D.DER_CTX_SALT,     D.CTX,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_SALT_OTH         = new DerivedSalt(D.DER_SALT_OTH,     D.NONE,    D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX_SALT_OTH     = new DerivedSalt(D.DER_CTX_SALT_OTH, D.CTX,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY              = new DerivedSalt(D.DER_NONE,         D.KEY,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX          = new DerivedSalt(D.DER_CTX,          D.KEY_CTX, D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_OTH          = new DerivedSalt(D.DER_OTH,          D.KEY,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX_OTH      = new DerivedSalt(D.DER_CTX_OTH,      D.KEY_CTX, D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_SALT         = new DerivedSalt(D.DER_SALT,         D.KEY,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX_SALT     = new DerivedSalt(D.DER_CTX_SALT,     D.KEY_CTX, D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_SALT_OTH     = new DerivedSalt(D.DER_SALT_OTH,     D.KEY,     D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX_SALT_OTH = new DerivedSalt(D.DER_CTX_SALT_OTH, D.KEY_CTX, D.PRF_ALG, D.DER_LEN_BYTES, D.ITER, D.DK_LEN, D.DER_ALG);
		public DerivedSalt(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2Context context, @NotNull final Pbkdf2Util.ALG alg, @Min(C.MIN_DER_BYTES_LEN) final int derivedSaltLen, @Min(C.MIN_ITERATIONS) final int iter, @Min(C.MIN_DK_BYTES_LEN) final int dkLenBytes, @NotNull final MacUtil.ALG mac) {
			this.encode = (rawInput) -> {
				final byte[] derivedSaltBytesForEncode = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLen], iter, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput));
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSaltBytesForEncode, iter, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(encodeDecode, new Pbkdf2ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final byte[] derivedSaltBytesForMatches = deriveSalt(mac, new Pbkdf2ClearParameters(context.clear(), new byte[derivedSaltLen], iter, dkLenBytes, alg.alg()), new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput));
				@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), derivedSaltBytesForMatches, iter, dkLenBytes, alg.alg());
				@NotNull final Pbkdf2ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(encodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				@NotNull final Pbkdf2SecretParameters constructedSecretParameters = new Pbkdf2SecretParameters(context.key(), context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using derived salt
		}
	}

	public static final class ConstantSalt extends IocEncoder {
		public static final ConstantSalt DEFAULT_NONE             = new ConstantSalt(D.CONST_NONE,         D.NONE,    D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX              = new ConstantSalt(D.CONST_CTX,          D.CTX,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_OTH              = new ConstantSalt(D.CONST_OTH,          D.NONE,    D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX_OTH          = new ConstantSalt(D.CONST_CTX_OTH,      D.CTX,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_SALT             = new ConstantSalt(D.CONST_SALT,         D.NONE,    D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX_SALT         = new ConstantSalt(D.CONST_CTX_SALT,     D.CTX,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_SALT_OTH         = new ConstantSalt(D.CONST_SALT_OTH,     D.NONE,    D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX_SALT_OTH     = new ConstantSalt(D.CONST_CTX_SALT_OTH, D.CTX,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY              = new ConstantSalt(D.CONST_NONE,         D.KEY,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX          = new ConstantSalt(D.CONST_CTX,          D.KEY_CTX, D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_OTH          = new ConstantSalt(D.CONST_OTH,          D.KEY,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX_OTH      = new ConstantSalt(D.CONST_CTX_OTH,      D.KEY_CTX, D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_SALT         = new ConstantSalt(D.CONST_SALT,         D.KEY,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX_SALT     = new ConstantSalt(D.CONST_CTX_SALT,     D.KEY_CTX, D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_SALT_OTH     = new ConstantSalt(D.CONST_SALT_OTH,     D.KEY,     D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX_SALT_OTH = new ConstantSalt(D.CONST_CTX_SALT_OTH, D.KEY_CTX, D.PRF_ALG, D.CONST_BYTES, D.ITER, D.DK_LEN);
		public ConstantSalt(@NotNull final Pbkdf2EncodeDecode encodeDecode, @NotNull final Pbkdf2Context context, @NotNull final Pbkdf2Util.ALG alg, @NotEmpty final byte[] constantSalt, @Min(C.MIN_ITERATIONS) final int iter, @Min(C.MIN_DK_BYTES_LEN) final int dkLenBytes) {
			@NotNull final Pbkdf2ClearParameters computedClearParameters = new Pbkdf2ClearParameters(context.clear(), constantSalt, iter, dkLenBytes, alg.alg());
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
				clearParameters.iter(),
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
			ByteUtil.byteArray(clearParameters.iter()),
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
			ByteUtil.byteArray(clearParameters.iter()),
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
		if (encodeDecode.flags().iter()) {
			parameters.add(Integer.valueOf(defaults.iter()));
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
        final byte[]  context    = (encodeDecode.flags().context()) ? encodeDecode.encoderDecoder().decodeFromString(parts[part++]) : defaults.context();
		final byte[]  salt       = (encodeDecode.flags().salt())    ? encodeDecode.encoderDecoder().decodeFromString(parts[part++]) : defaults.salt();
		final int     iter       = (encodeDecode.flags().iter())    ? Integer.parseInt(parts[part++])                               : defaults.iter();
		final int     dkLenBytes = (encodeDecode.flags().dkLen())   ? Integer.parseInt(parts[part++])                               : defaults.dkLenBytes();
		final String  alg        = (encodeDecode.flags().alg())     ? parts[part++]                                                 : defaults.alg();
		return new Pbkdf2ClearParameters(context, salt, iter, dkLenBytes, alg);
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

	// Constraints
	private static class C {
		private static final int MIN_RAND_BYTES_LEN = 8;
		private static final int MIN_DER_BYTES_LEN = 8;
		private static final int MIN_ITERATIONS = 1;
		private static final int MIN_DK_BYTES_LEN = 16;
	}

	// Defaults
	private static class D {
		private static final Pbkdf2Util.ALG PRF_ALG = Pbkdf2Util.ALG.PBKDF2WithHmacSHA256;
		private static final MacUtil.ALG DER_ALG = MacUtil.ALG.HmacSHA256;
		private static final int RAND_LEN_BYTES = 32;
		private static final int DER_LEN_BYTES = 32;
		private static final byte[] CONST_BYTES = "salt".getBytes(StandardCharsets.UTF_8);
		private static final int ITER = 600_000;
		private static final int DK_LEN = 32;
		private static final SecretKey DER_KEY = new SecretKeySpec("hmacsecretkeybytesvariablelength".getBytes(StandardCharsets.UTF_8), PRF_ALG.alg());
		private static final Pbkdf2Context NONE    = new Pbkdf2Context(null, new byte[0], new byte[0]);
		private static final Pbkdf2Context CTX     = new Pbkdf2Context(null, new byte[23], new byte[13]);
		private static final Pbkdf2Context KEY     = new Pbkdf2Context(DER_KEY, new byte[0], new byte[0]);
		private static final Pbkdf2Context KEY_CTX = new Pbkdf2Context(DER_KEY, new byte[23], new byte[13]);

	    private static final Base64Util.EncoderDecoder ENC_DEC = Base64Util.MIME;
		private static final String ENC_PARAM = ":";
		private static final String DEC_PARAM = ENC_PARAM;
	    private static final String ENC_HASH = "|";
	    private static final String DEC_HASH = "\\" + ENC_HASH;
	    private static final Pbkdf2EncodeDecodeSeparators SEP = new Pbkdf2EncodeDecodeSeparators(ENC_PARAM, DEC_PARAM, ENC_HASH, DEC_HASH);

		private static final Pbkdf2EncodeDecodeFlags FL_NONE           = new Pbkdf2EncodeDecodeFlags(false, false,  false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FL_CTX            = new Pbkdf2EncodeDecodeFlags(true,  false,  false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FL_SALT           = new Pbkdf2EncodeDecodeFlags(false, true,   false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FL_OTH          = new Pbkdf2EncodeDecodeFlags(false, false,  true,  true,  true);
		private static final Pbkdf2EncodeDecodeFlags FL_CTX_SALT       = new Pbkdf2EncodeDecodeFlags(true,  true,   false, false, false);
		private static final Pbkdf2EncodeDecodeFlags FL_CTX_OTH      = new Pbkdf2EncodeDecodeFlags(true,  false,  true,  true,  true);
		private static final Pbkdf2EncodeDecodeFlags FL_SALT_OTH     = new Pbkdf2EncodeDecodeFlags(false, true,   true,  true,  true);
		private static final Pbkdf2EncodeDecodeFlags FL_CTX_SALT_OTH = new Pbkdf2EncodeDecodeFlags(true,  true,   true,  true,  true);

		// RandomSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final Pbkdf2EncodeDecode RAND_SALT           = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_SALT);
		private static final Pbkdf2EncodeDecode RAND_CTX_SALT       = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_SALT);
		private static final Pbkdf2EncodeDecode RAND_SALT_OTH       = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_SALT_OTH);
		private static final Pbkdf2EncodeDecode RAND_CTX_SALT_OTH   = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_SALT_OTH);

		// DerivedSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final Pbkdf2EncodeDecode DER_NONE            = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_NONE);
		private static final Pbkdf2EncodeDecode DER_CTX             = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX);
		private static final Pbkdf2EncodeDecode DER_SALT            = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_SALT);
		private static final Pbkdf2EncodeDecode DER_OTH             = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_OTH);
		private static final Pbkdf2EncodeDecode DER_CTX_SALT        = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_SALT);
		private static final Pbkdf2EncodeDecode DER_CTX_OTH         = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_OTH);
		private static final Pbkdf2EncodeDecode DER_SALT_OTH        = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_SALT_OTH);
		private static final Pbkdf2EncodeDecode DER_CTX_SALT_OTH    = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_SALT_OTH);

		// ConstantSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final Pbkdf2EncodeDecode CONST_NONE          = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_NONE);
		private static final Pbkdf2EncodeDecode CONST_CTX           = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX);
		private static final Pbkdf2EncodeDecode CONST_SALT          = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_SALT);
		private static final Pbkdf2EncodeDecode CONST_OTH           = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_OTH);
		private static final Pbkdf2EncodeDecode CONST_CTX_SALT      = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_SALT);
		private static final Pbkdf2EncodeDecode CONST_CTX_OTH       = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_OTH);
		private static final Pbkdf2EncodeDecode CONST_SALT_OTH      = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_SALT_OTH);
		private static final Pbkdf2EncodeDecode CONST_CTX_SALT_OTH  = new Pbkdf2EncodeDecode(ENC_DEC, SEP, FL_CTX_SALT_OTH);
	}
}
