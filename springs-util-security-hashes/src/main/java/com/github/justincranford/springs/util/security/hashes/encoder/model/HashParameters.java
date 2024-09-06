package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface HashParameters {
	@NotNull public EncodeDecode encodeDecode();
	@NotNull public byte[] canonicalBytes();
	@NotEmpty public List<Object> canonicalObjects();
	@NotNull public byte[] compute(@NotNull final byte[] saltBytes, @NotNull final CharSequence inputString);
	@NotNull public Boolean recompute(
		@Min(0)  final int defaultSaltBytesLen,
		@Min(0)  final int decodedSaltBytesLen,
		@NotNull final HashParameters decodedParameters,
		@Min(0)  final int decodedComputeLength
	);
	@NotEmpty public HashParameters decode(@NotEmpty List<String> parts, @NotNull EncodeDecode encodeDecode);
}
