package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashConstantsAndHashPeppers(
	@NotNull HashConstants hashConstants,
	@NotNull HashPeppers hashPeppers
) { }
