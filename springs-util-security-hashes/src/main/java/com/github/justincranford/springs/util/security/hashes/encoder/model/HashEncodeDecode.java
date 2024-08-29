package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.Base64Util;

import jakarta.validation.constraints.NotNull;

public record HashEncodeDecode(
	@NotNull Base64Util.EncoderDecoder encoderDecoder,
	@NotNull HashEncodeDecodeSeparators separators,
	@NotNull EncodeDecodeFlags flags
) {
	// do nothing
}