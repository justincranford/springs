package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;

@SuppressWarnings("nls")
public record HashEncodeDecodeSeparators(
	@NotEmpty String encodeParameters,
	@NotEmpty String decodeParameters,
	@NotEmpty String encodeHash,
	@NotEmpty String decodeHash
) {
	private static final String ENC_PARAM = ":";
	private static final String DEC_PARAM = ENC_PARAM;
    private static final String ENC_HASH = "|";
    private static final String DEC_HASH = "\\" + ENC_HASH;

    public static final HashEncodeDecodeSeparators CB = new HashEncodeDecodeSeparators(ENC_PARAM, DEC_PARAM, ENC_HASH, DEC_HASH);
}
