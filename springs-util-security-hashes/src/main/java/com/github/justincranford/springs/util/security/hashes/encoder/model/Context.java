package com.github.justincranford.springs.util.security.hashes.encoder.model;

import javax.crypto.SecretKey;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public interface Context {
	@Null public SecretKey key();
	@NotNull public byte[] secret();
	@NotNull public byte[] clear();
}
