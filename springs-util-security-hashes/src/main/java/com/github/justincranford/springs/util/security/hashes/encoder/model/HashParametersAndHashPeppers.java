package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashParametersAndHashPeppers(
	@NotNull HashParameters hashParameters,
	@NotNull HashPeppers peppersForMacs
) { }
