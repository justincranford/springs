package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;

public record HashConstantParametersAndHashVariableParametersAndHash(
	@NotNull HashConstantParametersAndHashVariableParameters hashConstantParametersAndHashVariableParameters,
	@NotNull byte[] hashBytes
) { }
