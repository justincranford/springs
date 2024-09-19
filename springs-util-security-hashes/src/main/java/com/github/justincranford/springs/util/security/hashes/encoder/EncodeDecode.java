package com.github.justincranford.springs.util.security.hashes.encoder;

import com.github.justincranford.springs.util.basic.Base64Util;

import jakarta.validation.constraints.NotNull;

@SuppressWarnings("nls")
public record EncodeDecode(
	@NotNull Base64Util.EncoderDecoder encoderDecoder,
	@NotNull String separator,
	@NotNull EncodeDecode.Flags flags
) {
    public static final String C = ":";

	public record Flags(
		boolean encodeHashInputVariables,
		boolean encodeHashInputConstants
	) {
		public static final Flags FL_NONE     = new Flags(false,  false);
		public static final Flags FL_SALT     = new Flags(true,   false);
		public static final Flags FL_OTH      = new Flags(false,  true);
		public static final Flags FL_SALT_OTH = new Flags(true,   true);
	}

	public static final EncodeDecode STD_C_NONE          = new EncodeDecode(Base64Util.STD,  EncodeDecode.C, EncodeDecode.Flags.FL_NONE);
	public static final EncodeDecode STD_C_SALT          = new EncodeDecode(Base64Util.STD,  EncodeDecode.C, EncodeDecode.Flags.FL_SALT);
	public static final EncodeDecode STD_C_OTH           = new EncodeDecode(Base64Util.STD,  EncodeDecode.C, EncodeDecode.Flags.FL_OTH);
	public static final EncodeDecode STD_C_SALT_OTH      = new EncodeDecode(Base64Util.STD,  EncodeDecode.C, EncodeDecode.Flags.FL_SALT_OTH);
	public static final EncodeDecode URL_C_NONE          = new EncodeDecode(Base64Util.URL,  EncodeDecode.C, EncodeDecode.Flags.FL_NONE);
	public static final EncodeDecode URL_C_SALT          = new EncodeDecode(Base64Util.URL,  EncodeDecode.C, EncodeDecode.Flags.FL_SALT);
	public static final EncodeDecode URL_C_OTH           = new EncodeDecode(Base64Util.URL,  EncodeDecode.C, EncodeDecode.Flags.FL_OTH);
	public static final EncodeDecode URL_C_SALT_OTH      = new EncodeDecode(Base64Util.URL,  EncodeDecode.C, EncodeDecode.Flags.FL_SALT_OTH);
	public static final EncodeDecode MIME_C_NONE         = new EncodeDecode(Base64Util.MIME, EncodeDecode.C, EncodeDecode.Flags.FL_NONE);
	public static final EncodeDecode MIME_C_SALT         = new EncodeDecode(Base64Util.MIME, EncodeDecode.C, EncodeDecode.Flags.FL_SALT);
	public static final EncodeDecode MIME_C_OTH          = new EncodeDecode(Base64Util.MIME, EncodeDecode.C, EncodeDecode.Flags.FL_OTH);
	public static final EncodeDecode MIME_CB_SALT_OTH     = new EncodeDecode(Base64Util.MIME, EncodeDecode.C, EncodeDecode.Flags.FL_SALT_OTH);
}