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
import com.github.justincranford.springs.util.security.hashes.util.MacUtil;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls", "hiding"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2Encoder {
	public static final class RandomSalt extends FlexiblePbkdf2Encoder {
		public static final RandomSalt DEFAULT1 = new RandomSalt(Default1.CONTEXT, Default1.ALG, Default1.RANDOM_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN);
		public RandomSalt(final Context context, final Pbkdf2Encoder.ALG alg, final int randomSaltLength, final int iterations, final int dkLenBytes) {
			super(RandomSalt.class, context, alg, (rawInput) -> SecureRandomUtil.randomBytes(randomSaltLength), iterations, dkLenBytes);
		}
	}
	public static final class DerivedSalt extends FlexiblePbkdf2Encoder {
		public static final DerivedSalt DEFAULT1 = new DerivedSalt(Default1.CONTEXT, Default1.ALG, Default1.DERIVED_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN, Default1.DERIVED_SALT_MAC);
		public DerivedSalt(final Context context, final Pbkdf2Encoder.ALG alg, final int derivedSaltLength, final int iterations, final int dkLenBytes, final MacUtil.ALG mac) {
			super(DerivedSalt.class, context, alg, (rawInput) -> derivedSalt(mac, new ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, alg.alg()), new SecretParameters(context.secret(), rawInput)), iterations, dkLenBytes);
		}
	}
	public static final class ConstantSalt extends FlexiblePbkdf2Encoder {
		public static final ConstantSalt DEFAULT1 = new ConstantSalt(Default1.CONTEXT, Default1.ALG, Default1.CONSTANT_SALT, Default1.ITERATIONS, Default1.DK_LEN);
		public ConstantSalt(final Context context, final Pbkdf2Encoder.ALG alg, final byte[] constantSalt, final int iterations, final int dkLenBytes) {
			super(ConstantSalt.class, context, alg, (rawInput) -> constantSalt, iterations, dkLenBytes);
		}
	}

	private static abstract class FlexiblePbkdf2Encoder implements PasswordEncoder {
		private final Function<CharSequence, String> encode;
		private final BiFunction<CharSequence, String, Boolean> matches;
		private final Function<String, Boolean> upgradeEncoding;
		public FlexiblePbkdf2Encoder(
			final Class<? extends FlexiblePbkdf2Encoder> clazz,
			final Context context,
			final Pbkdf2Encoder.ALG alg,
			final Function<CharSequence, byte[]> saltSupplier,
			final int iterations,
			final int dkLenBytes
		) {
			final BiFunction<ClearParameters, CharSequence, byte[]> computeClearHash = (clearParameters, rawInput) -> computeClearHash(clearParameters, new SecretParameters(context.secret(), rawInput));
			if (clazz.equals(ConstantSalt.class) || clazz.equals(DerivedSalt.class)) {
				final ClearParameters clearParameters = new ClearParameters(context.clear(), saltSupplier.apply(""), iterations, dkLenBytes, alg.name());
				this.encode = (rawInput) ->  encodeClearHash(computeClearHash.apply(clearParameters, rawInput)); // omit  clear parameters
				this.matches = (rawInput, encodedClearHash) -> Boolean.valueOf(MessageDigest.isEqual(decodeClearHash(encodedClearHash), computeClearHash.apply(clearParameters, rawInput)));
				this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using constant salt
			} else if (clazz.equals(RandomSalt.class)) {
				this.encode = (rawInput) -> {
					final ClearParameters clearParameters = new ClearParameters(context.clear(), saltSupplier.apply(rawInput), iterations, dkLenBytes, alg.name());
					return encodeParametersAndHash(new ClearParametersAndClearHash(clearParameters, computeClearHash.apply(clearParameters, rawInput))); // include parameters in output
				};
				this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
					final ClearParametersAndClearHash clearParametersAndClearHash = decodeClearParametersAndClearHash(encodedClearParametersAndClearHash);
					final byte[] clearHashChallenge = computeClearHash.apply(clearParametersAndClearHash.clearParameters(), rawInput);
					return Boolean.valueOf(MessageDigest.isEqual(clearParametersAndClearHash.clearHash(), clearHashChallenge));
				};
				this.upgradeEncoding = (encodedClearParametersAndClearHash) -> {
					if (encodedClearParametersAndClearHash == null || encodedClearParametersAndClearHash.length() == 0) {
						return Boolean.FALSE;
					}
					final ClearParametersAndClearHash clearParametersAndClearHash = decodeClearParametersAndClearHash(encodedClearParametersAndClearHash);
					final ClearParameters clearParameters = clearParametersAndClearHash.clearParameters();
					final byte[] clearHash = clearParametersAndClearHash.clearHash();
					return Boolean.valueOf(clearHash.length < dkLenBytes || clearParameters.iterations() < iterations);
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

	private static byte[] computeClearHash(final ClearParameters clearParameters, final SecretParameters secretParameters) {
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

    public static byte[] derivedSalt(final MacUtil.ALG mac, final ClearParameters clearParameters, final SecretParameters secretParameters) {
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

	private static record Context(byte[] clear, byte[] secret) { }
    private static record ClearParameters(byte[] clearContext, byte[] salt, int iterations, int dkLenBytes, String alg) { }
    private static record ClearParametersAndClearHash(ClearParameters clearParameters, byte[] clearHash) { }
    private static record SecretParameters(byte[] secretContext, CharSequence rawInput) { }

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
		private static final Base64Util.Encoder BASE64_UTIL_ENCODER = Base64Util.STD_ENCODE;
		private static final Base64Util.Decoder BASE64_UTIL_DECODER = Base64Util.STD_DECODE;

		private static final Context CONTEXT = new Context(new byte[0], new byte[0]);
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

    public static String encodeParameters(final ClearParameters clearParameters) {
		return StringUtil.toString("", Default1.SEPARATOR_ENCODE_PARAMETERS, "",
			List.of(
				Default1.BASE64_UTIL_ENCODER.string(clearParameters.clearContext()),
				Default1.BASE64_UTIL_ENCODER.string(clearParameters.salt()),
				Integer.valueOf(clearParameters.iterations()),
				Integer.valueOf(clearParameters.dkLenBytes()),
				clearParameters.alg()
			)
		);
    }

    public static ClearParameters decodeClearParameters(final String clearEncodedParameters) {
        final String[] parts = clearEncodedParameters.split(Default1.SEPARATOR_DECODE_PARAMETERS);
        int part = 0;
        return new ClearParameters(Default1.BASE64_UTIL_DECODER.bytes(parts[part++]), Default1.BASE64_UTIL_DECODER.bytes(parts[part++]), Integer.parseInt(parts[part++]), Integer.parseInt(parts[part++]), parts[part++]);
    }

    public static String encodeParametersAndHash(final ClearParametersAndClearHash clearParametersAndClearHash) {
		return encodeParameters(clearParametersAndClearHash.clearParameters()) + Default1.SEPARATOR_ENCODE_HASH +  encodeClearHash(clearParametersAndClearHash.clearHash());
    }
    public static ClearParametersAndClearHash decodeClearParametersAndClearHash(final String clearParametersAndClearHash) {
        final String[] parts = clearParametersAndClearHash.split(Default1.SEPARATOR_DECODE_HASH);
        return new ClearParametersAndClearHash(decodeClearParameters(parts[0]), decodeClearHash(parts[1]));
    }

    private static String encodeClearHash(final byte[] hash) {
		return Default1.BASE64_UTIL_ENCODER.string(hash);
	}
	private static byte[] decodeClearHash(final String encodedHash) {
		return Default1.BASE64_UTIL_DECODER.bytes(encodedHash);
	}
}
