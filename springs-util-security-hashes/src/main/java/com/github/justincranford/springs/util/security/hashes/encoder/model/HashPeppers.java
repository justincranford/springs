package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashPeppers(
	@NotNull HashPepperSalt hashSaltPepper,
	@NotNull HashPepperPreHash hashPreHashPepper,
	@NotNull HashPepperPostHash hashPostHashPepper
) { }
