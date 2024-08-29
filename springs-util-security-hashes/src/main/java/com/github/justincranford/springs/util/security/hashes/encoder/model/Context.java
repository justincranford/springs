package com.github.justincranford.springs.util.security.hashes.encoder.model;

import javax.crypto.SecretKey;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public record Context(
	@Null SecretKey macKeyDeriveSalt,
	@NotNull byte[] secret,
	@NotNull byte[] clear
) {
	// do nothing
}