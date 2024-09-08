package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record CipherConstantParametersAndCipherPeppers(
	@NotNull CipherConstantParameters hashConstantParameters,
	@NotNull CipherPeppers peppersForMacs
) { }
