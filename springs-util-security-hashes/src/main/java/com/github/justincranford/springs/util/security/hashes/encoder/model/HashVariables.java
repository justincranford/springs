package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;

public record HashVariables(
	@NotEmpty byte[] hashSaltBytes
) {
	public byte[] canonicalBytes() {
		return this.hashSaltBytes;
	}
}
