package com.github.justincranford.springs.util.security.hashes.encoder;

import com.github.justincranford.springs.util.basic.Base64Util;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

@SuppressWarnings("nls")
public record EncodeDecode(
	@NotNull Base64Util.EncoderDecoder encoderDecoder,
	@NotNull EncodeDecode.Separators separators,
	@NotNull EncodeDecode.Flags flags
) {
	public record Separators(
		@NotEmpty String intraParameters,
		@NotEmpty String parametersVsHash
	) {
	    public static final Separators CB = new Separators(":", "|");
	}

	public record Flags(
		boolean encodeHashVariables,
		boolean encodeHashConstants
	) {
		public static final Flags FL_NONE     = new Flags(false,  false);
		public static final Flags FL_SALT     = new Flags(true,   false);
		public static final Flags FL_OTH      = new Flags(false,  true);
		public static final Flags FL_SALT_OTH = new Flags(true,   true);
	}

	public static final EncodeDecode STD_CB_NONE          = new EncodeDecode(Base64Util.STD,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_NONE);
	public static final EncodeDecode STD_CB_SALT          = new EncodeDecode(Base64Util.STD,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_SALT);
	public static final EncodeDecode STD_CB_OTH           = new EncodeDecode(Base64Util.STD,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_OTH);
	public static final EncodeDecode STD_CB_SALT_OTH      = new EncodeDecode(Base64Util.STD,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_SALT_OTH);
	public static final EncodeDecode URL_CB_NONE          = new EncodeDecode(Base64Util.URL,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_NONE);
	public static final EncodeDecode URL_CB_SALT          = new EncodeDecode(Base64Util.URL,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_SALT);
	public static final EncodeDecode URL_CB_OTH           = new EncodeDecode(Base64Util.URL,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_OTH);
	public static final EncodeDecode URL_CB_SALT_OTH      = new EncodeDecode(Base64Util.URL,  EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_SALT_OTH);
	public static final EncodeDecode MIME_CB_NONE         = new EncodeDecode(Base64Util.MIME, EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_NONE);
	public static final EncodeDecode MIME_CB_SALT         = new EncodeDecode(Base64Util.MIME, EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_SALT);
	public static final EncodeDecode MIME_CB_OTH          = new EncodeDecode(Base64Util.MIME, EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_OTH);
	public static final EncodeDecode MIME_CB_SALT_OTH     = new EncodeDecode(Base64Util.MIME, EncodeDecode.Separators.CB, EncodeDecode.Flags.FL_SALT_OTH);
}