package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.ByteUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashEncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.model.Parameters;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public record Pbkdf2ParametersV1 (
	@Min(Constraints.MIN_ITER) int iter,
	@Min(Constraints.MIN_HASH_BYTES_LEN) int hashBytesLen,
	@NotEmpty Pbkdf2Algorithm algorithm,
	@NotNull HashEncodeDecode hashEncodeDecode
) implements Parameters {
	@Override
	public byte[] canonicalEncodedBytes() {
		return ArrayUtil.concat(
			ByteUtil.byteArray(this.iter()),
			ByteUtil.byteArray(this.hashBytesLen()),
			this.algorithm().canonicalIdBytes(),
			this.hashEncodeDecode().encoderDecoder().canonicalIdBytes()
		);
	}

	@Override
	public byte[] computeHash(@NotNull final byte[] saltBytes, @NotNull final CharSequence rawInput) {
		try {
			final PBEKeySpec spec = new PBEKeySpec(
				rawInput.toString().toCharArray(),
				saltBytes.clone(),
				this.iter(),
				this.hashBytesLen() * 8
			);
			final SecretKeyFactory skf = SecretKeyFactory.getInstance(this.algorithm().value());
			final byte[] hashBytes = skf.generateSecret(spec).getEncoded();
			return hashBytes;
		} catch (GeneralSecurityException ex) {
			throw new IllegalStateException("Could not create hash", ex);
		}
	}

	@Override
	public Boolean upgradeEncoding(
		@Min(0)  final int defaultSaltBytesLen,
		@Min(0)  final int decodedSaltBytesLen,
		@NotNull final Parameters decodedParameters,
		@Min(0)  final int decodedHashLength
	) {
		final Pbkdf2ParametersV1 decodedParametersPbkdf2 = (Pbkdf2ParametersV1) decodedParameters;
		return Boolean.valueOf(
			   (defaultSaltBytesLen     != decodedSaltBytesLen)
			|| (this.iter()             != decodedParametersPbkdf2.iter())
			|| (this.algorithm()        != decodedParametersPbkdf2.algorithm())
			|| (this.hashEncodeDecode() != decodedParametersPbkdf2.hashEncodeDecode())
			|| (this.hashBytesLen()     != decodedHashLength)
		);
	}

	@Override
	@NotEmpty public List<Object> encodeParameters() {
		final List<Object> parametersToBeEncoded = new ArrayList<>(3);
		parametersToBeEncoded.add(Integer.valueOf(this.iter()));
		parametersToBeEncoded.add(Integer.valueOf(this.hashBytesLen()));
		parametersToBeEncoded.add(this.algorithm());
		return parametersToBeEncoded;
	}

	@Override
	@NotEmpty public Parameters decodeParameters(@NotNull final String[] parts, @Min(0) int partIndex, @NotNull final HashEncodeDecode hashEncodeDecode0) {
        int part = partIndex;
		final int                iterDecoded         = (hashEncodeDecode0.flags().parameters()) ? Integer.parseInt(parts[part++])        : this.iter();
		final int                hashBytesLenDecoded = (hashEncodeDecode0.flags().parameters()) ? Integer.parseInt(parts[part++])        : this.hashBytesLen();
		final Pbkdf2Algorithm    algorithmDecoded    = (hashEncodeDecode0.flags().parameters()) ? Pbkdf2Algorithm.valueOf(parts[part++]) : this.algorithm();
		final Pbkdf2ParametersV1 parametersDecoded   = new Pbkdf2ParametersV1(iterDecoded, hashBytesLenDecoded, algorithmDecoded, hashEncodeDecode0);
		return parametersDecoded;
	}

	public static class Constraints {
		public static final int MIN_RAND_BYTES_LEN = 8;		// Absolute Min: 64-bit,  Recommended Min: 256-bit/32-bytes
		public static final int MIN_DER_BYTES_LEN = 8;		// Absolute Min: 64-bit,  Recommended Min: 256-bit/32-bytes
		public static final int MIN_ITER = 1;				// Absolute Min: 1,       Recommended Min: 600_000
		public static final int MIN_HASH_BYTES_LEN = 16;	// Absolute Min: 128-bit, Recommended Min: 256-bit/32-bytes
	}
}
