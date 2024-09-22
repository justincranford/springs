package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import java.security.GeneralSecurityException;
import java.util.List;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.github.justincranford.springs.util.basic.ArrayUtil;
import com.github.justincranford.springs.util.basic.ByteUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.HashCodec;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputConstants;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.experimental.Accessors;

@Getter
@Accessors(fluent=true)
@SuppressWarnings({"nls"})
public class Pbkdf2InputConstantsV1 extends HashInputConstants {
	@Min(Constraints.MIN_ITER) private int iterations;

	public Pbkdf2InputConstantsV1(
		@NotNull final Pbkdf2AlgorithmV1 algorithm0,
		@NotNull final HashCodec codec0,
		@Min(CommonConstraints.MIN_HASH_BYTES_LEN) final int hashBytesLen0,
		@Min(Constraints.MIN_ITER) final int iterations0
	) {
		super(algorithm0, codec0, hashBytesLen0);
		this.iterations = iterations0;
	}

	@Override
	@NotNull public Pbkdf2AlgorithmV1 algorithm() {
		return (Pbkdf2AlgorithmV1) super.algorithm();
	}

	@Override
	@NotEmpty public byte[] canonicalBytes() {
		return ArrayUtil.concat(
			this.algorithm().asn1DerBytes(),
			ByteUtil.byteArray(this.iterations()),
			ByteUtil.byteArray(this.hashBytesLen())
		);
	}

	@Override
	@NotEmpty public List<String> canonicalObjects() {
		return List.of(
			this.algorithm().canonicalString(),
			Integer.toString(this.iterations()),
			Integer.toString(this.hashBytesLen())
		);
	}

	@Override
	@NotEmpty public HashInputConstants decode(
		@NotNull final List<String> parts
	) {
		final Pbkdf2AlgorithmV1      algorithmDecoded    = (this.codec().flags().encodeHashInputConstants()) ? Pbkdf2AlgorithmV1.canonicalString(parts.removeFirst()) : this.algorithm();
		final int                    iterationsDecoded   = (this.codec().flags().encodeHashInputConstants()) ? Integer.parseInt(parts.removeFirst())                  : this.iterations();
		final int                    hashBytesLenDecoded = (this.codec().flags().encodeHashInputConstants()) ? Integer.parseInt(parts.removeFirst())                  : this.hashBytesLen();
		final Pbkdf2InputConstantsV1 parametersDecoded   = new Pbkdf2InputConstantsV1(algorithmDecoded, super.codec(), hashBytesLenDecoded, iterationsDecoded);
		return parametersDecoded;
	}

	@Override
	public byte[] compute(
		@NotNull @Min(Constraints.MIN_SALT_BYTES_LEN) final byte[]       variableInputConstantsBytes,
		@NotNull @Min(Constraints.MIN_RAW_INPUT_SIZE) final CharSequence rawInput
	) {
		try {
			final PBEKeySpec spec = new PBEKeySpec(
				rawInput.toString().toCharArray(),
				variableInputConstantsBytes.clone(),
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
		@Min(Constraints.MIN_SALT_BYTES_LEN)       final int                expectedHashInputVariablesBytesLength,
		@Min(Constraints.MIN_SALT_BYTES_LEN)       final int                actualHashInputVariablesBytesLength,
		@NotNull                                   final HashInputConstants actualHashInputConstants,
		@Min(CommonConstraints.MIN_HASH_BYTES_LEN) final int                expectedHashBytesLength,
		@Min(CommonConstraints.MIN_HASH_BYTES_LEN) final int                actualHashBytesLength
	) {
		final Pbkdf2InputConstantsV1 actualConstantParametersPbkdf2 = (Pbkdf2InputConstantsV1) actualHashInputConstants;
		return Boolean.valueOf(
			   (expectedHashInputVariablesBytesLength != actualHashInputVariablesBytesLength)
			|| (this.algorithm()                      != actualConstantParametersPbkdf2.algorithm())
			|| (this.iterations()                     != actualConstantParametersPbkdf2.iterations())
			|| (expectedHashBytesLength               != actualHashBytesLength)
			|| (this.codec()                          != actualConstantParametersPbkdf2.codec())
		);
	}

	public static class Constraints {
		public static final int MIN_RAW_INPUT_SIZE = 0;	// Absolute Min (Testing): 0-bit,  Recommended Min (Production): 0-bit/0-bytes
		public static final int MIN_SALT_BYTES_LEN = 0;	// Absolute Min (Testing): 0-bit,  Recommended Min (Production): 256-bit/32-bytes
		public static final int MIN_ITER = 1;			// Absolute Min (Testing): 1,      Recommended Min (Production): 600_000
	}
}
