package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashInputConstantsAndHashPeppers(
	@NotNull HashInputConstants hashInputConstants,
	@NotNull HashPeppers hashPeppers
) { }
