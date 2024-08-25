package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.function.BiFunction;
import java.util.function.Function;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.util.MessageDigestUtil;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls", "hiding"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2Encoder {
	public static final class RandomSalt extends FlexiblePbkdf2Encoder {
		public static final RandomSalt DEFAULT1 = new RandomSalt(Default1.CONTEXT, Default1.PRF, Default1.RANDOM_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN);
		public RandomSalt(final Context context, final PRF prf, final int randomSaltLength, final int iterations, final int dkLenBytes) {
			super(RandomSalt.class, context, prf, (rawInput) -> SecureRandomUtil.randomBytes(randomSaltLength), iterations, dkLenBytes);
		}
	}
	public static final class DerivedSalt extends FlexiblePbkdf2Encoder {
		public static final DerivedSalt DEFAULT1 = new DerivedSalt(Default1.CONTEXT, Default1.PRF, Default1.DERIVED_SALT_LENGTH, Default1.ITERATIONS, Default1.DK_LEN, Default1.DERIVED_SALT_DIGEST);
		public DerivedSalt(final Context context, final PRF prf, final int derivedSaltLength, final int iterations, final int dkLenBytes, final DIGEST digest) {
			super(DerivedSalt.class, context, prf, (rawInput) -> derivedSalt(digest, new ClearParameters(context.clear(), new byte[derivedSaltLength], iterations, dkLenBytes, prf.prf()), new SecretParameters(context.secret(), rawInput)), iterations, dkLenBytes);
		}
	}
	public static final class ConstantSalt extends FlexiblePbkdf2Encoder {
		public static final ConstantSalt DEFAULT1 = new ConstantSalt(Default1.CONTEXT, Default1.PRF, Default1.CONSTANT_SALT, Default1.ITERATIONS, Default1.DK_LEN);
		public ConstantSalt(final Context context, final PRF prf, final byte[] constantSalt, final int iterations, final int dkLenBytes) {
			super(ConstantSalt.class, context, prf, (rawInput) -> constantSalt, iterations, dkLenBytes);
		}
	}

	private static abstract class FlexiblePbkdf2Encoder implements PasswordEncoder {
		private final Function<CharSequence, String> encode;
		private final BiFunction<CharSequence, String, Boolean> matches;
		private final Function<String, Boolean> upgradeEncoding;
		public FlexiblePbkdf2Encoder(
			final Class<? extends FlexiblePbkdf2Encoder> clazz,
			final Context context,
			final PRF prf,
			final Function<CharSequence, byte[]> saltSupplier,
			final int iterations,
			final int dkLenBytes
		) {
			final BiFunction<ClearParameters, CharSequence, byte[]> computeClearHash = (clearParameters, rawInput) -> computeClearHash(clearParameters, new SecretParameters(context.secret(), rawInput));
			if (clazz.equals(ConstantSalt.class)) {
				final ClearParameters clearParameters = new ClearParameters(context.clear(), saltSupplier.apply(""), iterations, dkLenBytes, prf.name());
				this.encode = (rawInput) ->  encodeClearHash(computeClearHash.apply(clearParameters, rawInput)); // omit  clear parameters
				this.matches = (rawInput, encodedClearHash) -> Boolean.valueOf(MessageDigest.isEqual(decodeClearHash(encodedClearHash), computeClearHash.apply(clearParameters, rawInput)));
				this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using constant salt
			} else {
				this.encode = (rawInput) -> {
					final ClearParameters clearParameters = new ClearParameters(context.clear(), saltSupplier.apply(rawInput), iterations, dkLenBytes, prf.name());
					return encodeParametersAndHash(new ClearParametersAndClearHash(clearParameters, computeClearHash.apply(clearParameters, rawInput))); // include parameters in output
				};
				this.matches = (rawInput, encodedClearParametersAndClearHash) -> {
					final ClearParametersAndClearHash clearParametersAndClearHash = decodeClearParametersAndClearHash(encodedClearParametersAndClearHash);
					final byte[] clearHashChallenge = computeClearHash.apply(clearParametersAndClearHash.clearParameters(), rawInput);
					return Boolean.valueOf(MessageDigest.isEqual(clearParametersAndClearHash.clearHash(), clearHashChallenge));
				};
				if (clazz.equals(DerivedSalt.class)) {
					this.upgradeEncoding = (encodedClearParametersAndClearHash) -> Boolean.FALSE; // never upgrade encoding when using derived salt
				} else if (clazz.equals(RandomSalt.class)) {
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
			final SecretKeyFactory skf = SecretKeyFactory.getInstance(clearParameters.prf());
			return skf.generateSecret(spec).getEncoded();
		} catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not create hash", ex);
		}

	}

    public static byte[] derivedSalt(final DIGEST digest, final ClearParameters clearParameters, final SecretParameters secretParameters) {
		return MessageDigestUtil.messageDigest(
			digest.alg(),
			canonicalEncodedParametersForDerivedSalt(clearParameters, secretParameters)
		);
	}

	private static byte[] canonicalEncodedParametersForDerivedSalt(final ClearParameters clearParameters, final SecretParameters secretParameters) {
		final byte[] rawInputBytes = secretParameters.rawInput().toString().getBytes(StandardCharsets.UTF_8);
		final byte[] secretContextBytes = secretParameters.secretContext().toString().getBytes(StandardCharsets.UTF_8);
		final int saltLength = clearParameters.salt().length;
		final byte[] clearContextBytes = clearParameters.clearContext();
		final int iterations = clearParameters.iterations();
		final int dkLenBytes = clearParameters.dkLenBytes();
		final byte[] prfBytes = clearParameters.prf().getBytes(StandardCharsets.UTF_8);

		return ByteBuffer.allocate(rawInputBytes.length + secretContextBytes.length + 4 + clearContextBytes.length + 4 + 4 + prfBytes.length)
			.order(ByteOrder.BIG_ENDIAN)
			.put(rawInputBytes) // different derived salt per different password
			.put(secretContextBytes) // different derived salt per different password
			.putInt(saltLength)
			.put(clearContextBytes)
			.putInt(iterations)
			.putInt(dkLenBytes)
			.put(prfBytes)
			.array();
	}

	private static record Context(byte[] clear, byte[] secret) { }
    private static record ClearParameters(byte[] clearContext, byte[] salt, int iterations, int dkLenBytes, String prf) { }
    private static record ClearParametersAndClearHash(ClearParameters clearParameters, byte[] clearHash) { }
    private static record SecretParameters(byte[] secretContext, CharSequence rawInput) { }

    public enum PRF {
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
		private PRF(final String alg, final int lenBytes) {
			this.alg = alg;
			this.lenBytes = lenBytes;
		}
		public String prf() {
			return this.alg;
		}
		public int lengthBytes() {
			return this.lenBytes;
		}
	}

    public enum DIGEST {
		SHA1("SHA-1", 20),
		SHA224("SHA-224", 28),
		SHA256("SHA-256", 32),
		SHA384("SHA-384", 48),
		SHA512("SHA-512", 64),
		SHA384_224("SHA-512/224", 48),
		SHA512_256("SHA-512/255", 64),
		SHA3_224("SHA3-224", 28),
		SHA3_256("SHA3-256", 32),
		SHA3_384("SHA3-384", 48),
		SHA3_512("SHA3-512", 64),
		SHA3_384_224("SHA3-512/224", 48),
		SHA3_512_256("SHA3-512/255", 64);
		private final String alg;
		private final int lenBytes;
		private DIGEST(final String alg, final int lenBytes) {
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
		private static final Context CONTEXT = new Context(new byte[0], new byte[0]);
		private static final PRF PRF = Pbkdf2Encoder.PRF.PBKDF2WithHmacSHA256;
		private static final int RANDOM_SALT_LENGTH = 32;
		private static final int DERIVED_SALT_LENGTH = 32;
		private static final byte[] CONSTANT_SALT = new byte[0];
		private static final int ITERATIONS = 600_000;
		private static final int DK_LEN = 32;
		private static final DIGEST DERIVED_SALT_DIGEST = Pbkdf2Encoder.DIGEST.SHA256;
		private static final String SEPARATOR_PARAMETERS = ":";
	    private static final String SEPARATOR_HASH = ",";
	}

    public static String encodeParameters(final ClearParameters clearParameters) {
    	return new StringBuilder()
			.append(Base64Util.STD_ENCODE.string(clearParameters.clearContext()))
			.append(Default1.SEPARATOR_PARAMETERS)
			.append(Base64Util.STD_ENCODE.string(clearParameters.salt()))
			.append(Default1.SEPARATOR_PARAMETERS)
			.append(clearParameters.iterations())
			.append(Default1.SEPARATOR_PARAMETERS)
			.append(clearParameters.dkLenBytes())
			.append(Default1.SEPARATOR_PARAMETERS)
			.append(clearParameters.prf())
   			.toString();
    }
    public static ClearParameters decodeClearParameters(final String clearEncodedParameters) {
        final String[] parts = clearEncodedParameters.split(Default1.SEPARATOR_PARAMETERS);
        int part = 0;
        return new ClearParameters(Base64Util.STD_DECODE.bytes(parts[part++]), Base64Util.STD_DECODE.bytes(parts[part++]), Integer.parseInt(parts[part++]), Integer.parseInt(parts[part++]), parts[part++]);
    }

    public static String encodeParametersAndHash(final ClearParametersAndClearHash clearParametersAndClearHash) {
		return encodeParameters(clearParametersAndClearHash.clearParameters()) + Default1.SEPARATOR_HASH +  encodeClearHash(clearParametersAndClearHash.clearHash());
    }
    public static ClearParametersAndClearHash decodeClearParametersAndClearHash(final String clearParametersAndClearHash) {
        final String[] parts = clearParametersAndClearHash.split(Default1.SEPARATOR_HASH);
        return new ClearParametersAndClearHash(decodeClearParameters(parts[0]), decodeClearHash(parts[1]));
    }

    private static String encodeClearHash(final byte[] hash) {
		return Base64Util.STD_ENCODE.string(hash);
	}
	private static byte[] decodeClearHash(final String encodedHash) {
		return Base64Util.STD_DECODE.bytes(encodedHash);
	}
}
