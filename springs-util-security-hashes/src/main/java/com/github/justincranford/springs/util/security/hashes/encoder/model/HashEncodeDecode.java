package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.Base64Util;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings("nls")
public record HashEncodeDecode(
	@NotNull Base64Util.EncoderDecoder encoderDecoder,
	@NotNull HashEncodeDecode.Separators separators,
	@NotNull HashEncodeDecode.Flags flags
) {
	public record Separators(
		@NotEmpty String encodeParameters,
		@NotEmpty String decodeParameters,
		@NotEmpty String encodeHash,
		@NotEmpty String decodeHash
	) {
		private static final String ENC_PARAM = ":";
		private static final String DEC_PARAM = ENC_PARAM;
	    private static final String ENC_HASH = "|";
	    private static final String DEC_HASH = "\\" + ENC_HASH;

	    public static final Separators CB = new Separators(ENC_PARAM, DEC_PARAM, ENC_HASH, DEC_HASH);
	}

	public record Flags(
		boolean context,
		boolean salt,
		boolean other
	) {
		public static final Flags FL_NONE         = new Flags(false, false,  false);
		public static final Flags FL_CTX          = new Flags(true,  false,  false);
		public static final Flags FL_SALT         = new Flags(false, true,   false);
		public static final Flags FL_OTH          = new Flags(false, false,  true);
		public static final Flags FL_CTX_SALT     = new Flags(true,  true,   false);
		public static final Flags FL_CTX_OTH      = new Flags(true,  false,  true);
		public static final Flags FL_SALT_OTH     = new Flags(false, true,   true);
		public static final Flags FL_CTX_SALT_OTH = new Flags(true,  true,   true);
	}
}