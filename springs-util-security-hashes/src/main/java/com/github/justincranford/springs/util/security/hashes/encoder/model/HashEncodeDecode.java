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
		@NotEmpty String intraParameters,
		@NotEmpty String parametersVsHash
	) {
	    public static final Separators CB = new Separators(":", "|");
	}

	public record Flags(
		boolean hashSalt,
		boolean hashParameters
	) {
		public static final Flags FL_NONE     = new Flags(false,  false);
		public static final Flags FL_SALT     = new Flags(true,   false);
		public static final Flags FL_OTH      = new Flags(false,  true);
		public static final Flags FL_SALT_OTH = new Flags(true,   true);
	}

	public static final HashEncodeDecode STD_CB_NONE          = new HashEncodeDecode(Base64Util.STD,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_NONE);
	public static final HashEncodeDecode STD_CB_SALT          = new HashEncodeDecode(Base64Util.STD,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT);
	public static final HashEncodeDecode STD_CB_OTH           = new HashEncodeDecode(Base64Util.STD,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_OTH);
	public static final HashEncodeDecode STD_CB_SALT_OTH      = new HashEncodeDecode(Base64Util.STD,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT_OTH);
	public static final HashEncodeDecode URL_CB_NONE          = new HashEncodeDecode(Base64Util.URL,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_NONE);
	public static final HashEncodeDecode URL_CB_SALT          = new HashEncodeDecode(Base64Util.URL,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT);
	public static final HashEncodeDecode URL_CB_OTH           = new HashEncodeDecode(Base64Util.URL,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_OTH);
	public static final HashEncodeDecode URL_CB_SALT_OTH      = new HashEncodeDecode(Base64Util.URL,  HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT_OTH);
	public static final HashEncodeDecode MIME_CB_NONE         = new HashEncodeDecode(Base64Util.MIME, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_NONE);
	public static final HashEncodeDecode MIME_CB_SALT         = new HashEncodeDecode(Base64Util.MIME, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT);
	public static final HashEncodeDecode MIME_CB_OTH          = new HashEncodeDecode(Base64Util.MIME, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_OTH);
	public static final HashEncodeDecode MIME_CB_SALT_OTH     = new HashEncodeDecode(Base64Util.MIME, HashEncodeDecode.Separators.CB, HashEncodeDecode.Flags.FL_SALT_OTH);
}