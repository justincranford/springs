package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashPeppers(
	@NotNull HashPepperInputVariables inputVariables, // EX: Hmac (salt), Cipher (IV)
	@NotNull HashPepperPreHash preHash,
	@NotNull HashPepperPostHash postHash
) { }
