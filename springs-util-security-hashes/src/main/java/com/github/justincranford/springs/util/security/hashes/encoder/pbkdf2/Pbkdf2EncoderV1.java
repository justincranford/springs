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
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashEncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.IocEncoder;
import com.github.justincranford.springs.util.security.hashes.encoder.model.SecretParameters;
import com.github.justincranford.springs.util.security.hashes.util.MacUtil;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2EncoderV1 {
	private static record Pbkdf2ClearParametersOther(@Min(C.MIN_ITER) int iter, @Min(C.MIN_DK_BYTES_LEN) int dkLenBytes, @NotEmpty String alg) implements ClearParameters.Other { }

	public static final class RandomSalt extends IocEncoder {
		public static final RandomSalt DEFAULT_SALT             = new RandomSalt(ED.RAND_SALT,         KC.NONE,    KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public static final RandomSalt DEFAULT_CTX_SALT         = new RandomSalt(ED.RAND_CTX_SALT,     KC.CTX,     KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public static final RandomSalt DEFAULT_SALT_OTH         = new RandomSalt(ED.RAND_SALT_OTH,     KC.NONE,    KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public static final RandomSalt DEFAULT_CTX_SALT_OTH     = new RandomSalt(ED.RAND_CTX_SALT_OTH, KC.CTX,     KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_SALT         = new RandomSalt(ED.RAND_SALT,         KC.KEY,     KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_CTX_SALT     = new RandomSalt(ED.RAND_CTX_SALT,     KC.KEY_CTX, KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_SALT_OTH     = new RandomSalt(ED.RAND_SALT_OTH,     KC.KEY,     KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public static final RandomSalt DEFAULT_KEY_CTX_SALT_OTH = new RandomSalt(ED.RAND_CTX_SALT_OTH, KC.KEY_CTX, KC.PRF_ALG, KC.RAND_LEN_BYTES, KC.ITER, KC.DK_LEN);
		public RandomSalt(@NotNull final HashEncodeDecode hashEncodeDecode, @NotNull final Context context, @NotNull final Pbkdf2Util.ALG alg, @Min(C.MIN_RAND_BYTES_LEN) final int randomSaltLen, @Min(C.MIN_ITER) final int iter, @Min(C.MIN_DK_BYTES_LEN) final int dkLenBytes) {
			this.encode = (rawInput) -> {
				final byte[] randomSaltBytesForEncode = SecureRandomUtil.randomBytes(randomSaltLen);
				final ClearParameters computedClearParameters = new ClearParameters(context.clear(), randomSaltBytesForEncode, new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg()));
				final SecretParameters constructedSecretParameters = new SecretParameters(context.macKeyDeriveSalt(), context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(hashEncodeDecode, new ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final byte[] poisonSaltBytesForMatches = null;
				final ClearParameters computedClearParameters = new ClearParameters(context.clear(), poisonSaltBytesForMatches, new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg()));
				final ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(hashEncodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				final SecretParameters constructedSecretParameters = new SecretParameters(context.macKeyDeriveSalt(), context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> {
				if (encodedClearParametersAndClearHash == null || encodedClearParametersAndClearHash.length() == 0) {
					return Boolean.FALSE;
				}
				final byte[] poisonSaltBytesForUpgradeEncoding = null; 
				final ClearParameters computedClearParameters = new ClearParameters(context.clear(), poisonSaltBytesForUpgradeEncoding, new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg()));
				final ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(hashEncodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				final ClearParameters parsedClearParameters = parsedClearParametersAndClearHash.clearParameters();
				final Pbkdf2ClearParametersOther parsedClearParametersOther = (Pbkdf2ClearParametersOther) parsedClearParametersAndClearHash.clearParameters().other();
				final byte[] parsedClearHash = parsedClearParametersAndClearHash.clearHash();
				return Boolean.valueOf(
					   (!MessageDigest.isEqual(context.clear(), parsedClearParameters.context()))
					|| (randomSaltLen != parsedClearParameters.salt().length)
					|| (iter != parsedClearParametersOther.iter())
					|| (dkLenBytes != parsedClearHash.length)
					|| (!alg.alg().equals(parsedClearParametersOther.alg()))
				);
			};
		}
	}

	public static final class DerivedSalt extends IocEncoder {
		public static final DerivedSalt DEFAULT_NONE             = new DerivedSalt(ED.DER_NONE,         KC.NONE,    KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX              = new DerivedSalt(ED.DER_CTX,          KC.CTX,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_OTH              = new DerivedSalt(ED.DER_OTH,          KC.NONE,    KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX_OTH          = new DerivedSalt(ED.DER_CTX_OTH,      KC.CTX,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_SALT             = new DerivedSalt(ED.DER_SALT,         KC.NONE,    KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX_SALT         = new DerivedSalt(ED.DER_CTX_SALT,     KC.CTX,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_SALT_OTH         = new DerivedSalt(ED.DER_SALT_OTH,     KC.NONE,    KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_CTX_SALT_OTH     = new DerivedSalt(ED.DER_CTX_SALT_OTH, KC.CTX,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY              = new DerivedSalt(ED.DER_NONE,         KC.KEY,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX          = new DerivedSalt(ED.DER_CTX,          KC.KEY_CTX, KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_OTH          = new DerivedSalt(ED.DER_OTH,          KC.KEY,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX_OTH      = new DerivedSalt(ED.DER_CTX_OTH,      KC.KEY_CTX, KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_SALT         = new DerivedSalt(ED.DER_SALT,         KC.KEY,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX_SALT     = new DerivedSalt(ED.DER_CTX_SALT,     KC.KEY_CTX, KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_SALT_OTH     = new DerivedSalt(ED.DER_SALT_OTH,     KC.KEY,     KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public static final DerivedSalt DEFAULT_KEY_CTX_SALT_OTH = new DerivedSalt(ED.DER_CTX_SALT_OTH, KC.KEY_CTX, KC.PRF_ALG, KC.DER_LEN_BYTES, KC.ITER, KC.DK_LEN, KC.DER_ALG);
		public DerivedSalt(@NotNull final HashEncodeDecode hashEncodeDecode, @NotNull final Context context, @NotNull final Pbkdf2Util.ALG alg, @Min(C.MIN_DER_BYTES_LEN) final int derivedSaltLen, @Min(C.MIN_ITER) final int iter, @Min(C.MIN_DK_BYTES_LEN) final int dkLenBytes, @NotNull final MacUtil.ALG mac) {
			this.encode = (rawInput) -> {
				final SecretParameters constructedSecretParameters = new SecretParameters(context.macKeyDeriveSalt(), context.secret(), rawInput);
				final byte[] derivedSaltBytesForEncode = deriveSalt(mac, new ClearParameters(context.clear(), new byte[derivedSaltLen], new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg())), constructedSecretParameters);
				final ClearParameters computedClearParameters = new ClearParameters(context.clear(), derivedSaltBytesForEncode, new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg()));
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(hashEncodeDecode, new ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final SecretParameters constructedSecretParameters = new SecretParameters(context.macKeyDeriveSalt(), context.secret(), rawInput);
				final byte[] derivedSaltBytesForMatches = deriveSalt(mac, new ClearParameters(context.clear(), new byte[derivedSaltLen], new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg())), constructedSecretParameters);
				final ClearParameters computedClearParameters = new ClearParameters(context.clear(), derivedSaltBytesForMatches, new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg()));
				final ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(hashEncodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using derived salt
		}
	}

	public static final class ConstantSalt extends IocEncoder {
		public static final ConstantSalt DEFAULT_NONE             = new ConstantSalt(ED.CONST_NONE,         KC.NONE,    KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX              = new ConstantSalt(ED.CONST_CTX,          KC.CTX,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_OTH              = new ConstantSalt(ED.CONST_OTH,          KC.NONE,    KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX_OTH          = new ConstantSalt(ED.CONST_CTX_OTH,      KC.CTX,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_SALT             = new ConstantSalt(ED.CONST_SALT,         KC.NONE,    KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX_SALT         = new ConstantSalt(ED.CONST_CTX_SALT,     KC.CTX,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_SALT_OTH         = new ConstantSalt(ED.CONST_SALT_OTH,     KC.NONE,    KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_CTX_SALT_OTH     = new ConstantSalt(ED.CONST_CTX_SALT_OTH, KC.CTX,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY              = new ConstantSalt(ED.CONST_NONE,         KC.KEY,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX          = new ConstantSalt(ED.CONST_CTX,          KC.KEY_CTX, KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_OTH          = new ConstantSalt(ED.CONST_OTH,          KC.KEY,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX_OTH      = new ConstantSalt(ED.CONST_CTX_OTH,      KC.KEY_CTX, KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_SALT         = new ConstantSalt(ED.CONST_SALT,         KC.KEY,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX_SALT     = new ConstantSalt(ED.CONST_CTX_SALT,     KC.KEY_CTX, KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_SALT_OTH     = new ConstantSalt(ED.CONST_SALT_OTH,     KC.KEY,     KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public static final ConstantSalt DEFAULT_KEY_CTX_SALT_OTH = new ConstantSalt(ED.CONST_CTX_SALT_OTH, KC.KEY_CTX, KC.PRF_ALG, KC.CONST_BYTES, KC.ITER, KC.DK_LEN);
		public ConstantSalt(@NotNull final HashEncodeDecode hashEncodeDecode, @NotNull final Context context, @NotNull final Pbkdf2Util.ALG alg, @NotEmpty final byte[] constantSalt, @Min(C.MIN_ITER) final int iter, @Min(C.MIN_DK_BYTES_LEN) final int dkLenBytes) {
			final ClearParameters computedClearParameters = new ClearParameters(context.clear(), constantSalt, new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg.alg()));
			super.encode = (rawInput) ->  {
				final SecretParameters constructedSecretParameters = new SecretParameters(context.macKeyDeriveSalt(), context.secret(), rawInput);
				final byte[] computedClearHash = computeClearHash(computedClearParameters, constructedSecretParameters);
				return encodeClearParametersAndClearHash(hashEncodeDecode, new ClearParametersAndClearHash(computedClearParameters, computedClearHash));
			};
			super.matches = (rawInput, encodedClearParametersAndClearHash) -> {
				final ClearParametersAndClearHash parsedClearParametersAndClearHash = decodeClearParametersAndClearHash(hashEncodeDecode, encodedClearParametersAndClearHash, computedClearParameters);
				final SecretParameters constructedSecretParameters = new SecretParameters(context.macKeyDeriveSalt(), context.secret(), rawInput);
				final byte[] computedClearHashChallenge = computeClearHash(parsedClearParametersAndClearHash.clearParameters(), constructedSecretParameters);
				return Boolean.valueOf(MessageDigest.isEqual(parsedClearParametersAndClearHash.clearHash(), computedClearHashChallenge));
			};
			super.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using constant salt
		}
	}

	private static byte[] computeClearHash(@NotNull final ClearParameters clearParameters, @NotNull final SecretParameters secretParameters) {
		try {
			final Pbkdf2ClearParametersOther pbkdf2ClearParametersOther = (Pbkdf2ClearParametersOther) clearParameters.other();
			final PBEKeySpec spec = new PBEKeySpec(
				secretParameters.rawInput().toString().toCharArray(),
				ArrayUtil.concat(secretParameters.context(), clearParameters.context(), clearParameters.salt()),
				pbkdf2ClearParametersOther.iter(),
				pbkdf2ClearParametersOther.dkLenBytes() * 8
			);
			final SecretKeyFactory skf = SecretKeyFactory.getInstance(pbkdf2ClearParametersOther.alg());
			return skf.generateSecret(spec).getEncoded();
		} catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not create hash", ex);
		}
	}

    public static byte[] deriveSalt(@NotNull final MacUtil.ALG mac, @NotNull final ClearParameters clearParameters, @NotNull final SecretParameters secretParameters) {
    	return (secretParameters.key() == null)
			? deriveSaltWithConstructedHmacKey(mac, clearParameters, secretParameters)
			: derivedSaltWithInputHmacKey(mac, clearParameters, secretParameters);
	}

	private static byte[] deriveSaltWithConstructedHmacKey(@NotNull final MacUtil.ALG mac, @NotNull final ClearParameters clearParameters, @NotNull final SecretParameters secretParameters) {
		final Pbkdf2ClearParametersOther pbkdf2ClearParametersOther = (Pbkdf2ClearParametersOther) clearParameters.other();
		final byte[] keyBytes = ArrayUtil.concat(
			secretParameters.rawInput().toString().getBytes(StandardCharsets.UTF_8),
			secretParameters.context().toString().getBytes(StandardCharsets.UTF_8)
		);
		final byte[] dataChunks = ArrayUtil.concat(
			ByteUtil.byteArray(clearParameters.salt().length), // length, not the actual value, because this method derives the actual value
			clearParameters.context(),
			ByteUtil.byteArray(pbkdf2ClearParametersOther.iter()),
			ByteUtil.byteArray(pbkdf2ClearParametersOther.dkLenBytes()),
			pbkdf2ClearParametersOther.alg().getBytes(StandardCharsets.UTF_8)
		);
		return MacUtil.hmac(mac.alg(), new SecretKeySpec(keyBytes, pbkdf2ClearParametersOther.alg()), dataChunks);
	}

	private static byte[] derivedSaltWithInputHmacKey(@NotNull final MacUtil.ALG mac, @NotNull final ClearParameters clearParameters, @NotNull final SecretParameters secretParameters) {
		final Pbkdf2ClearParametersOther pbkdf2ClearParametersOther = (Pbkdf2ClearParametersOther) clearParameters.other();
		final byte[] dataChunks = ArrayUtil.concat(
			secretParameters.rawInput().toString().getBytes(StandardCharsets.UTF_8),
			secretParameters.context().toString().getBytes(StandardCharsets.UTF_8),
			ByteUtil.byteArray(clearParameters.salt().length), // length, not the actual value, because this method derives the actual value
			clearParameters.context(),
			ByteUtil.byteArray(pbkdf2ClearParametersOther.iter()),
			ByteUtil.byteArray(pbkdf2ClearParametersOther.dkLenBytes()),
			pbkdf2ClearParametersOther.alg().getBytes(StandardCharsets.UTF_8)
		);
		return MacUtil.hmac(mac.alg(), secretParameters.key(), dataChunks);
	}

    public static String encodeClearParameters(@NotNull final HashEncodeDecode hashEncodeDecode, @NotNull final ClearParameters defaults) {
		final Pbkdf2ClearParametersOther pbkdf2ClearParametersOther = (Pbkdf2ClearParametersOther) defaults.other();
		final List<Object> parameters = new ArrayList<>(5);
		if (hashEncodeDecode.flags().context()) {
			parameters.add(hashEncodeDecode.encoderDecoder().encodeToString(defaults.context()));
		}
		if (hashEncodeDecode.flags().salt()) {
			parameters.add(hashEncodeDecode.encoderDecoder().encodeToString(defaults.salt()));
		}
		if (hashEncodeDecode.flags().other()) {
			parameters.add(Integer.valueOf(pbkdf2ClearParametersOther.iter()));
		}
		if (hashEncodeDecode.flags().other()) {
			parameters.add(Integer.valueOf(pbkdf2ClearParametersOther.dkLenBytes()));
		}
		if (hashEncodeDecode.flags().other()) {
			parameters.add(pbkdf2ClearParametersOther.alg());
		}
		return StringUtil.toString("", hashEncodeDecode.separators().encodeParameters(), "", parameters);
    }

    public static ClearParameters decodeClearParameters(@NotNull final HashEncodeDecode hashEncodeDecode, final String clearEncodedParameters, @NotNull final ClearParameters defaults) {
		final Pbkdf2ClearParametersOther pbkdf2ClearParametersOther = (Pbkdf2ClearParametersOther) defaults.other();
        final String[] parts = clearEncodedParameters.split(hashEncodeDecode.separators().decodeParameters());
        int part = 0;
        final byte[]  context    = (hashEncodeDecode.flags().context()) ? hashEncodeDecode.encoderDecoder().decodeFromString(parts[part++]) : defaults.context();
		final byte[]  salt       = (hashEncodeDecode.flags().salt())    ? hashEncodeDecode.encoderDecoder().decodeFromString(parts[part++]) : defaults.salt();
		final int     iter       = (hashEncodeDecode.flags().other())  ? Integer.parseInt(parts[part++])                                    : pbkdf2ClearParametersOther.iter();
		final int     dkLenBytes = (hashEncodeDecode.flags().other())  ? Integer.parseInt(parts[part++])                                    : pbkdf2ClearParametersOther.dkLenBytes();
		final String  alg        = (hashEncodeDecode.flags().other())  ? parts[part++]                                                      : pbkdf2ClearParametersOther.alg();
		return new ClearParameters(context, salt, new Pbkdf2ClearParametersOther(iter, dkLenBytes, alg));
    }

    public static String encodeClearParametersAndClearHash(@NotNull final HashEncodeDecode hashEncodeDecode, @NotNull final ClearParametersAndClearHash clearParametersAndClearHash) {
		final String encodeClearParameters = encodeClearParameters(hashEncodeDecode, clearParametersAndClearHash.clearParameters());
		final String encodeClearHash = encodeClearHash(hashEncodeDecode, clearParametersAndClearHash.clearHash());
		if (encodeClearParameters.isEmpty()) {
			return encodeClearHash;
		}
		return encodeClearParameters + hashEncodeDecode.separators().encodeHash() +  encodeClearHash;
    }
    public static ClearParametersAndClearHash decodeClearParametersAndClearHash(@NotNull final HashEncodeDecode hashEncodeDecode, @NotNull final String clearParametersAndClearHash, @NotNull final ClearParameters defaults) {
        final String[] parts = clearParametersAndClearHash.split(hashEncodeDecode.separators().decodeHash());
        int part = 0;
		return new ClearParametersAndClearHash(decodeClearParameters(hashEncodeDecode, (parts.length == 1) ? "" : parts[part++], defaults), decodeClearHash(hashEncodeDecode, parts[part++]));
    }

    private static String encodeClearHash(@NotNull final HashEncodeDecode hashEncodeDecode, @NotEmpty final byte[] hash) {
		return hashEncodeDecode.encoderDecoder().encodeToString(hash);
	}
	private static byte[] decodeClearHash(@NotNull final HashEncodeDecode hashEncodeDecode, @NotEmpty final String encodedHash) {
		return hashEncodeDecode.encoderDecoder().decodeFromString(encodedHash);
	}

	// Constraints
	private static class C {
		private static final int MIN_RAND_BYTES_LEN = 8;
		private static final int MIN_DER_BYTES_LEN = 8;
		private static final int MIN_ITER = 1;
		private static final int MIN_DK_BYTES_LEN = 16;
	}

	// Key+Context
	private static class KC {
		private static final Pbkdf2Util.ALG PRF_ALG = Pbkdf2Util.ALG.PBKDF2WithHmacSHA256;
		private static final MacUtil.ALG DER_ALG = MacUtil.ALG.HmacSHA256;
		private static final int RAND_LEN_BYTES = 32;
		private static final int DER_LEN_BYTES = 32;
		private static final byte[] CONST_BYTES = "salt".getBytes(StandardCharsets.UTF_8);
		private static final int ITER = 600_000;
		private static final int DK_LEN = 32;
		private static final SecretKey DER_KEY = new SecretKeySpec("hmacsecretkeybytesvariablelength".getBytes(StandardCharsets.UTF_8), PRF_ALG.alg());
		private static final Context NONE    = new Context(null, new byte[0], new byte[0]);
		private static final Context CTX     = new Context(null, new byte[23], new byte[13]);
		private static final Context KEY     = new Context(DER_KEY, new byte[0], new byte[0]);
		private static final Context KEY_CTX = new Context(DER_KEY, new byte[23], new byte[13]);
	}

	// Parameters
	private static class ED {

		// RandomSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final HashEncodeDecode RAND_SALT           = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT);
		private static final HashEncodeDecode RAND_CTX_SALT       = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_SALT);
		private static final HashEncodeDecode RAND_SALT_OTH       = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT_OTH);
		private static final HashEncodeDecode RAND_CTX_SALT_OTH   = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_SALT_OTH);

		// DerivedSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final HashEncodeDecode DER_NONE            = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_NONE);
		private static final HashEncodeDecode DER_CTX             = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX);
		private static final HashEncodeDecode DER_SALT            = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT);
		private static final HashEncodeDecode DER_OTH             = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_OTH);
		private static final HashEncodeDecode DER_CTX_SALT        = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_SALT);
		private static final HashEncodeDecode DER_CTX_OTH         = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_OTH);
		private static final HashEncodeDecode DER_SALT_OTH        = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT_OTH);
		private static final HashEncodeDecode DER_CTX_SALT_OTH    = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_SALT_OTH);

		// ConstantSalt => EncoderDecoder + Separators + EncodeDecodeFlags
		private static final HashEncodeDecode CONST_NONE          = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_NONE);
		private static final HashEncodeDecode CONST_CTX           = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX);
		private static final HashEncodeDecode CONST_SALT          = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT);
		private static final HashEncodeDecode CONST_OTH           = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_OTH);
		private static final HashEncodeDecode CONST_CTX_SALT      = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_SALT);
		private static final HashEncodeDecode CONST_CTX_OTH       = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_OTH);
		private static final HashEncodeDecode CONST_SALT_OTH      = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT_OTH);
		private static final HashEncodeDecode CONST_CTX_SALT_OTH  = new HashEncodeDecode(Base64Util.STD, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_CTX_SALT_OTH);
	}
}
