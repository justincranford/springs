package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.Base64Util;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings({"nls"})
public record HashConstants(
	@NotNull  Base64Util.EncoderDecoder encoderDecoder,
	@NotEmpty String separator
) {
    public String encode(@NotEmpty final byte[] plain) {
		return this.encoderDecoder.encodeToString(plain);
	}
	public byte[] decode(@NotEmpty final String encoded) {
		return this.encoderDecoder.decodeFromString(encoded);
	}

    public static final HashConstants STD_B  = new HashConstants(Base64Util.STD,  "|");
    public static final HashConstants URL_B  = new HashConstants(Base64Util.URL,  "|");
    public static final HashConstants MIME_B = new HashConstants(Base64Util.MIME, "|");
}
