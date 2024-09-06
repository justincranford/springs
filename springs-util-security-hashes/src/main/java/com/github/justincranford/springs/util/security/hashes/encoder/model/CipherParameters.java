package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface CipherParameters {
	@NotNull public EncodeDecode encodeDecode();
	@NotNull public byte[] canonicalBytes();
	@NotNull public byte[] compute(@NotNull final byte[] nonceBytes, final byte[] aadBytes, @NotNull final CharSequence inputString);
	@NotNull public Boolean recompute(
		@Min(0)  final int defaultNonceBytesLen,
		@Min(0)  final int decodedNonceBytesLen,
		@NotNull final CipherParameters decodedParameters,
		@Min(0)  final int decodedComputeLength
	);
	@NotEmpty public List<Object> canonicalEncodeObjects();
	@NotEmpty public CipherParameters decode(@NotNull List<String> parts, @NotNull EncodeDecode encodeDecode);
}
