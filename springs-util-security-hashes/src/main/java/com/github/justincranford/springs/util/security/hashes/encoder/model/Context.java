package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.Null;

public interface Context {
	@Null public byte[] clear();
	@Null public byte[] secret();
}
