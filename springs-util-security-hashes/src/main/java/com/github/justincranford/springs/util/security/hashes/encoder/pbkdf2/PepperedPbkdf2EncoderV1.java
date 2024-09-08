package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.pepper.PepperedHashEncoderV1;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashConstantParametersAndHashPeppers;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class PepperedPbkdf2EncoderV1 {
	public static final class RandomSalt extends PepperedHashEncoderV1 {
		public RandomSalt(@NotNull HashConstantParametersAndHashPeppers parametersAndMacs, @Min(Constraints.MIN_RAND_BYTES_LEN) int saltBytesLen) {
			super(parametersAndMacs, (rawInput) -> SecureRandomUtil.randomBytes(saltBytesLen));
		}
	}

	public static final class DerivedSalt extends PepperedHashEncoderV1 {
		public DerivedSalt(@NotNull HashConstantParametersAndHashPeppers parametersAndMacs, @Min(Constraints.MIN_DER_BYTES_LEN) int saltBytesLen) {
			super(parametersAndMacs, (rawInput) -> {
				if (parametersAndMacs.peppersForMacs().hashSaltPepper() == null) {
					throw new RuntimeException("PreSalt Mac required to guarantee unique, deterministic salt will be derived per unique input");
				}
				return new byte[saltBytesLen]; // equivalent to ConstantSalt with all 0x00 byte array, but PreSalt Mac is required
			});
		}
	}

	public static final class ConstantSalt extends PepperedHashEncoderV1 {
		public ConstantSalt(@NotNull HashConstantParametersAndHashPeppers parametersAndMacs, @NotEmpty byte[] saltBytes) {
			super(parametersAndMacs, (rawInput) -> saltBytes);
		}
	}

	public static final class Constraints {
		public static final int MIN_RAND_BYTES_LEN = 8;		// Absolute Min: 64-bit,  Recommended Min: 256-bit/32-bytes
		public static final int MIN_DER_BYTES_LEN = 8;		// Absolute Min: 64-bit,  Recommended Min: 256-bit/32-bytes
	}
}
