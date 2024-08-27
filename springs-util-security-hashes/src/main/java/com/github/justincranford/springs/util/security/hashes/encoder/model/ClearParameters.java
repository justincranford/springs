package com.github.justincranford.springs.util.security.hashes.encoder.model;

public interface ClearParameters {
	public byte[] context();
	public byte[] salt();
}
