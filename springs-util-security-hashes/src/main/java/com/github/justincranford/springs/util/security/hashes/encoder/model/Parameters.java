package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.List;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface Parameters {
	@NotNull public HashEncodeDecode hashEncodeDecode();
	@NotNull public byte[] canonicalEncodedBytes();
	@NotNull public byte[] computeHash(@NotNull final byte[] saltBytes, @NotNull final CharSequence inputString);
	@NotNull public Boolean upgradeEncoding(
		@Min(0)  final int defaultSaltBytesLen,
		@Min(0)  final int decodedSaltBytesLen,
		@NotNull final Parameters decodedParameters,
		@Min(0)  final int decodedHashLength
	);
	@NotEmpty public List<Object> encodeParameters();
	@NotEmpty public Parameters decodeParameters(@NotNull String[] parts, @Min(0) int partIndex, @NotNull HashEncodeDecode hashEncodeDecode);
}
