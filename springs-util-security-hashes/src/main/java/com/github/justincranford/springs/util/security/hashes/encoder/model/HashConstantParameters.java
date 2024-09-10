package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2EncoderV1.Constraints;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface HashConstantParameters {
	@NotNull public EncodeDecode encodeDecode();
	@NotNull public byte[] canonicalBytes();
	@NotEmpty public List<Object> canonicalObjects();
	@NotNull public byte[] compute(@NotNull final byte[] saltBytes, @NotNull final CharSequence inputString);
	@NotNull public Boolean recompute(
		@Min(Constraints.MIN_SALT_BYTES_LEN) final int                    expectedSaltBytesLength,
		@Min(Constraints.MIN_SALT_BYTES_LEN) final int                    actualSaltBytesLength,
		@NotNull                             final HashConstantParameters actualConstantParameters,
		@Min(Constraints.MIN_HASH_BYTES_LEN) final int                    expectedHashBytesLength,
		@Min(Constraints.MIN_HASH_BYTES_LEN) final int                    actualHashBytesLength
	);
	@NotEmpty public HashConstantParameters decode(@NotEmpty List<String> parts, @NotNull EncodeDecode encodeDecode);
}
