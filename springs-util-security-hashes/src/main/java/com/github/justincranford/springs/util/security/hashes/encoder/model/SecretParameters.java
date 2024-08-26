package com.github.justincranford.springs.util.security.hashes.encoder.model;

public interface SecretParameters {
	public byte[] secretContext();
	public CharSequence rawInput();
}
