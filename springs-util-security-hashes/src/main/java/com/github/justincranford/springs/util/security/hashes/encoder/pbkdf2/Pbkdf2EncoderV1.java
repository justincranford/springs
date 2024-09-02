package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.AbstractEncoderV1;
import com.github.justincranford.springs.util.security.hashes.encoder.model.ParametersAndMacs;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class Pbkdf2EncoderV1 {
	public static final class RandomSalt extends AbstractEncoderV1 {
		public RandomSalt(@NotNull ParametersAndMacs parametersAndMacs, @Min(Pbkdf2ParametersV1.Constraints.MIN_RAND_BYTES_LEN) int saltBytesLen) {
			super(parametersAndMacs, (rawInput) -> SecureRandomUtil.randomBytes(saltBytesLen));
		}
	}

	public static final class DerivedSalt extends AbstractEncoderV1 {
		public DerivedSalt(@NotNull ParametersAndMacs parametersAndMacs, @Min(Pbkdf2ParametersV1.Constraints.MIN_DER_BYTES_LEN) int saltBytesLen) {
			super(parametersAndMacs, (rawInput) -> {
				if (parametersAndMacs.macs().preSalt() == null) {
					throw new RuntimeException("PreSalt Mac required to guarantee unique, deterministic salt will be derived per unique input");
				}
				return new byte[saltBytesLen]; // equivalent to ConstantSalt with all 0x00 byte array, but PreSalt Mac is required
			});
		}
	}

	public static final class ConstantSalt extends AbstractEncoderV1 {
		public ConstantSalt(@NotNull ParametersAndMacs parametersAndMacs, @NotEmpty byte[] saltBytes) {
			super(parametersAndMacs, (rawInput) -> saltBytes);
		}
	}
}
