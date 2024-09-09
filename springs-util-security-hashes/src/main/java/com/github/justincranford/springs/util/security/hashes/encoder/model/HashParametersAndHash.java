package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashParametersAndHash(
	@NotNull HashParameters hashParameters,
	@NotNull byte[] hashBytes
) { }
