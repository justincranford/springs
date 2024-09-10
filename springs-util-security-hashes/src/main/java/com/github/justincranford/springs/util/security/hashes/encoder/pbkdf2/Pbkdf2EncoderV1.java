package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.security.GeneralSecurityException;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.ByteUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParameters;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public record Pbkdf2EncoderV1 (
	@NotNull Pbkdf2Algorithm algorithm,
	@Min(Constraints.MIN_ITER) int iterations,
	@Min(Constraints.MIN_HASH_BYTES_LEN) int hashBytesLen,
	@NotNull EncodeDecode encodeDecode
) implements HashConstantParameters {
	@Override
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(
			this.algorithm().asn1DerBytes(),
			ByteUtil.byteArray(this.iterations()),
			ByteUtil.byteArray(this.hashBytesLen())
		);
	}

	@Override
	@NotEmpty public List<Object> canonicalObjects() {
		return List.of(
			this.algorithm().canonicalString(),
			Integer.valueOf(this.iterations()),
			Integer.valueOf(this.hashBytesLen())
		);
	}

	@Override
	@NotEmpty public HashConstantParameters decode(
		@NotNull final List<String> parts,
		@NotNull final EncodeDecode hashEncodeDecode0
	) {
		final Pbkdf2Algorithm algorithmDecoded    = (hashEncodeDecode0.flags().hashConstantParameters()) ? Pbkdf2Algorithm.canonicalString(parts.removeFirst()) : this.algorithm();
		final int             iterationsDecoded   = (hashEncodeDecode0.flags().hashConstantParameters()) ? Integer.parseInt(parts.removeFirst())                : this.iterations();
		final int             hashBytesLenDecoded = (hashEncodeDecode0.flags().hashConstantParameters()) ? Integer.parseInt(parts.removeFirst())                : this.hashBytesLen();
		final Pbkdf2EncoderV1 parametersDecoded   = new Pbkdf2EncoderV1(algorithmDecoded, iterationsDecoded, hashBytesLenDecoded, hashEncodeDecode0);
		return parametersDecoded;
	}

	@Override
	public byte[] compute(
		@NotNull @Min(Constraints.MIN_SALT_BYTES_LEN) final byte[]       saltBytes,
		@NotNull @Min(Constraints.MIN_RAW_INPUT_SIZE) final CharSequence rawInput
	) {
		try {
			final PBEKeySpec spec = new PBEKeySpec(
				rawInput.toString().toCharArray(),
				saltBytes.clone(),
				this.iterations(),
				this.hashBytesLen() * 8
			);
			final SecretKeyFactory skf = SecretKeyFactory.getInstance(this.algorithm().algorithm());
			final byte[] hashBytes = skf.generateSecret(spec).getEncoded();
			return hashBytes;
		} catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not create hash", ex);
		}
	}

	@Override
	public Boolean recompute(
		@Min(Constraints.MIN_SALT_BYTES_LEN) final int                    expectedSaltBytesLength,
		@Min(Constraints.MIN_SALT_BYTES_LEN) final int                    actualSaltBytesLength,
		@NotNull                             final HashConstantParameters actualConstantParameters,
		@Min(Constraints.MIN_HASH_BYTES_LEN) final int                    expectedHashBytesLength,
		@Min(Constraints.MIN_HASH_BYTES_LEN) final int                    actualHashBytesLength
	) {
		final Pbkdf2EncoderV1 actualConstantParametersPbkdf2 = (Pbkdf2EncoderV1) actualConstantParameters;
		return Boolean.valueOf(
			   (expectedSaltBytesLength != actualSaltBytesLength)
			|| (this.algorithm()        != actualConstantParametersPbkdf2.algorithm())
			|| (this.iterations()       != actualConstantParametersPbkdf2.iterations())
			|| (expectedHashBytesLength != actualHashBytesLength)
			|| (this.encodeDecode()     != actualConstantParametersPbkdf2.encodeDecode())
		);
	}

	public static class Constraints {
		public static final int MIN_RAW_INPUT_SIZE = 0;	// Absolute Min (Testing): 0-bit,  Recommended Min (Production): 0-bit/0-bytes
		public static final int MIN_SALT_BYTES_LEN = 0;	// Absolute Min (Testing): 0-bit,  Recommended Min (Production): 256-bit/32-bytes
		public static final int MIN_ITER = 1;			// Absolute Min (Testing): 1,      Recommended Min (Production): 600_000
		public static final int MIN_HASH_BYTES_LEN = 8;	// Absolute Min (Testing): 64-bit, Recommended Min (Production): 256-bit/32-bytes
	}
}
