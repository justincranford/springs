package com.github.justincranford.springs.util.security.hashes.encoder.model;

import javax.crypto.SecretKey;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Null;

public record SecretParameters(
	@Null SecretKey key,
	@Null byte[] context,
	@NotEmpty CharSequence rawInput
) {
	// do nothing
}
