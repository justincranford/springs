package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.Base64Util;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface Pepper {
	@NotNull public byte[] secretContext();	// may be empty (e.g. any-entropy N-byte value)
	@NotNull public byte[] clearContext();	// may be empty (e.g. "application1".getBytes(), "feature1".getBytes(), any-entropy N-byte value)
	@NotNull public byte[] compute(@NotEmpty final byte[] rawInput, @NotNull final byte[] additionalData);
	@NotNull public Base64Util.EncoderDecoder encoderDecoder();
}
