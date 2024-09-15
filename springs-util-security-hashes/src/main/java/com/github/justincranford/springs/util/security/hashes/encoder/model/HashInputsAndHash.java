package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashInputsAndHash(
	@NotNull HashInputs hashInputs,
	@NotNull byte[] hashBytes
) { }
