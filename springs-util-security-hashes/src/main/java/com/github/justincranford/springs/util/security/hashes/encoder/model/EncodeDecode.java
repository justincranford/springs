package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public interface EncodeDecode {
	@NotNull public EncoderDecoderAndSeparators encoderDecoderAndSeparators();
	@NotNull public EncodeDecodeFlags flags();
}
