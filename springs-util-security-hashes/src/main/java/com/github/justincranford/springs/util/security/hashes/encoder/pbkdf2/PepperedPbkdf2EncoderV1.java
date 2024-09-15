package com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2;

import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashInputConstantsAndHashPeppers;
import com.github.justincranford.springs.util.security.hashes.encoder.pepper.PepperedHashEncoderV1;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import com.github.justincranford.springs.util.security.hashes.encoder.model.HashPepperSalt;

@SuppressWarnings({"nls"})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
@Slf4j
public final class PepperedPbkdf2EncoderV1 {
	public static final class RandomSalt extends PepperedHashEncoderV1 {
		public RandomSalt(@NotNull HashInputConstantsAndHashPeppers parametersAndMacs, @Min(Constraints.MIN_RAND_BYTES_LEN) int saltBytesLen) {
			super(parametersAndMacs, (rawInput) -> SecureRandomUtil.randomBytes(saltBytesLen));
		}
	}

	public static final class DerivedSalt extends PepperedHashEncoderV1 {
		public DerivedSalt(@NotNull HashInputConstantsAndHashPeppers hashInputConstantsAndHashPeppers, @Min(Constraints.MIN_DER_BYTES_LEN) int saltBytesLen) {
			super(hashInputConstantsAndHashPeppers, (rawInput) -> {
				final HashPepperSalt hashPepperSalt = hashInputConstantsAndHashPeppers.hashPeppers().salt();
				if (hashPepperSalt == null) {
					throw new RuntimeException("DerivedSalt.HashSaltPepper cannot be null");
				}
				if ((hashPepperSalt.secretKey() != null) && (hashPepperSalt.secretContext() != null)) {
					log.warn("DerivedSalt.HashSaltPepper is recommended to have a secretKey, secretContext, or both");
				}
				return new byte[saltBytesLen]; // equivalent to ConstantSalt with all 0x00 byte array; but PreSalt Mac will pepper it
			});
		}
	}

	public static final class ConstantSalt extends PepperedHashEncoderV1 {
		public ConstantSalt(@NotNull HashInputConstantsAndHashPeppers hashInputConstantsAndHashPeppers, @NotEmpty byte[] saltBytes) {
			super(hashInputConstantsAndHashPeppers, (rawInput) -> saltBytes);
		}
	}

	public static final class Constraints {
		public static final int MIN_RAND_BYTES_LEN = 8;		// Absolute Min: 64-bit,  Recommended Min: 256-bit/32-bytes
		public static final int MIN_DER_BYTES_LEN = 8;		// Absolute Min: 64-bit,  Recommended Min: 256-bit/32-bytes
	}
}
