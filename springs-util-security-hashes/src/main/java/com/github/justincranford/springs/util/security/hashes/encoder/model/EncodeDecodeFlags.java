package com.github.justincranford.springs.util.security.hashes.encoder.model;

public record EncodeDecodeFlags(
	boolean context,
	boolean salt,
	boolean other
) {
	public static final EncodeDecodeFlags FL_NONE         = new EncodeDecodeFlags(false, false,  false);
	public static final EncodeDecodeFlags FL_CTX          = new EncodeDecodeFlags(true,  false,  false);
	public static final EncodeDecodeFlags FL_SALT         = new EncodeDecodeFlags(false, true,   false);
	public static final EncodeDecodeFlags FL_OTH          = new EncodeDecodeFlags(false, false,  true);
	public static final EncodeDecodeFlags FL_CTX_SALT     = new EncodeDecodeFlags(true,  true,   false);
	public static final EncodeDecodeFlags FL_CTX_OTH      = new EncodeDecodeFlags(true,  false,  true);
	public static final EncodeDecodeFlags FL_SALT_OTH     = new EncodeDecodeFlags(false, true,   true);
	public static final EncodeDecodeFlags FL_CTX_SALT_OTH = new EncodeDecodeFlags(true,  true,   true);
}
