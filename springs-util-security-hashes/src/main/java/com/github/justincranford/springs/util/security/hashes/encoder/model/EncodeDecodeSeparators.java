package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;

public record EncodeDecodeSeparators(
	@NotEmpty String encodeParameters,
	@NotEmpty String decodeParameters,
	@NotEmpty String encodeHash,
	@NotEmpty String decodeHash
) {
	// do nothing
}
