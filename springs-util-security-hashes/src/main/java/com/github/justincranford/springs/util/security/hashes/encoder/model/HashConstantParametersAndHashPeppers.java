package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashConstantParametersAndHashPeppers(
	@NotNull HashConstantParameters hashParameters,
	@NotNull HashPeppers peppersForMacs
) { }
