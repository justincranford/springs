package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Null;

public record ClearParameters(
	@Null byte[] context,
	@NotEmpty byte[] salt,
	@Null ClearParametersOther other
) {
	// do nothing
}
