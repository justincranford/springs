package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.Base64Util;

public interface EncodeDecode {
	public Base64Util.EncoderDecoder encoderDecoder();
	public EncodeDecodeSeparators separators();
	public EncodeDecodeFlags flags();
}
