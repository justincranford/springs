package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record ClearParametersAndClearHash(
	@NotNull ClearParameters clearParameters,
	@NotEmpty byte[] clearHash
) {
	// nothing
}
