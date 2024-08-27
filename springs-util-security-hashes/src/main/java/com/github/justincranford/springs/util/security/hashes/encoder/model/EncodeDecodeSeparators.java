package com.github.justincranford.springs.util.security.hashes.encoder.model;

public interface EncodeDecodeSeparators {
	public String encodeParameters();
	public String decodeParameters();
	public String encodeHash();
	public String decodeHash();
}
