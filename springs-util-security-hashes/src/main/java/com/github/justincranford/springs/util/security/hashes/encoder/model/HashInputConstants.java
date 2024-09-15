package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import com.github.justincranford.springs.util.basic.StringUtil;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2Algorithm;
import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2EncoderV1.Constraints;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface HashInputConstants {
	@NotNull public Pbkdf2Algorithm algorithm();
	@Min(Constraints.MIN_ITER) public int iterations();
	@Min(Constraints.MIN_HASH_BYTES_LEN) int hashBytesLen();
	@NotNull public EncodeDecode encodeDecode();
	@NotNull public byte[] canonicalBytes();
	@NotEmpty public List<Object> canonicalObjects();
	@NotNull public byte[] compute(@NotNull final byte[] saltBytes, @NotNull final CharSequence inputString);
	@NotNull public Boolean recompute(
		@Min(Constraints.MIN_SALT_BYTES_LEN) final int                expectedSaltBytesLength,
		@Min(Constraints.MIN_SALT_BYTES_LEN) final int                actualSaltBytesLength,
		@NotNull                             final HashInputConstants actualConstantParameters,
		@Min(Constraints.MIN_HASH_BYTES_LEN) final int                expectedHashBytesLength,
		@Min(Constraints.MIN_HASH_BYTES_LEN) final int                actualHashBytesLength
	);
	@NotEmpty public HashInputConstants decode(@NotEmpty List<String> parts);

	default public List<String> splitInputsVsHash(final String hashInputsAndHashEncoded) {
		return StringUtil.split(hashInputsAndHashEncoded, this.encodeDecode().separators().parametersVsHash());
	}

	default public List<String> splitInputs(@NotNull final String hashInputsEncoded) {
		return StringUtil.split(hashInputsEncoded, this.encodeDecode().separators().intraParameters());
	}

	default public String encode(@NotEmpty final byte[] plain) {
		return this.encodeDecode().encoderDecoder().encodeToString(plain);
	}
	default public byte[] decode(@NotEmpty final String encoded) {
		return this.encodeDecode().encoderDecoder().decodeFromString(encoded);
	}
}
