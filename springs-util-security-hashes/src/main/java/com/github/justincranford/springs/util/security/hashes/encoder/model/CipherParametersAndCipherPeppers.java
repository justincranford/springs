package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record CipherParametersAndCipherPeppers(
	@NotNull CipherParameters hashParameters,
	@NotNull CipherPeppers peppersForMacs
) { }
