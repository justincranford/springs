package com.github.justincranford.springs.util.security.hashes.encoder.model;

public interface ClearParametersAndClearHash {
	public ClearParameters clearParameters();
	public byte[] clearHash();
}
