package com.github.justincranford.springs.util.security.hashes.encoder.model;

public interface Context {
	public byte[] clear();
	public byte[] secret();
}
