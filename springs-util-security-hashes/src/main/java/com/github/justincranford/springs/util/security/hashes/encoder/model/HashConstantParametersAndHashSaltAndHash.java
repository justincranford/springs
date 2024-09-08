package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record HashConstantParametersAndHashSaltAndHash(
	@NotNull HashConstantParametersAndHashSalt hashParametersAndHashSalt,
	@NotEmpty byte[] hashBytes
) { }
