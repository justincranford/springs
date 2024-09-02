package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashPeppers(
	@NotNull HashSaltPepper hashSaltPepper,
	@NotNull HashPreHashPepper hashPreHashPepper,
	@NotNull HashPostHashPepper hashPostHashPepper
) { }
