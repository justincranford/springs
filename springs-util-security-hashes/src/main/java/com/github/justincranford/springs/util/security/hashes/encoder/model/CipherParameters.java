package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import com.github.justincranford.springs.util.security.hashes.encoder.EncodeDecode;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface CipherParameters {
	@NotNull public EncodeDecode encodeDecode();
	@NotEmpty public byte[] canonicalBytes();
	@NotEmpty public List<Object> canonicalObjects();
	@NotNull public byte[] compute(@NotNull final byte[] ivBytes, final byte[] aadBytes, @NotNull final CharSequence inputString);
	@NotNull public Boolean recompute(
		@Min(0)  final int defaultIvBytesLen,
		@Min(0)  final int decodedIvBytesLen,
		@Min(0)  final int defaultAadBytesLen,
		@Min(0)  final int decodedAadBytesLen,
		@NotNull final CipherParameters decodedParameters,
		@Min(0)  final int decodedComputeLength
	);
	@NotEmpty public CipherParameters decode(@NotEmpty List<String> parts, @NotNull EncodeDecode encodeDecode);
}
