package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.Base64Util;

import jakarta.validation.constraints.NotNull;

public interface EncodeDecode {
	@NotNull public Base64Util.EncoderDecoder encoderDecoder();
	@NotNull public EncodeDecodeSeparators separators();
	@NotNull public EncodeDecodeFlags flags();
}
