package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.security.hashes.encoder.pbkdf2.Pbkdf2EncoderV1.Pbkdf2EncodeDecodeFlags;

import jakarta.validation.constraints.NotNull;

public record EncodeDecode(
	@NotNull EncoderDecoderAndSeparators encoderDecoderAndSeparators,
	@NotNull Pbkdf2EncodeDecodeFlags flags
) {
	// do nothing
}