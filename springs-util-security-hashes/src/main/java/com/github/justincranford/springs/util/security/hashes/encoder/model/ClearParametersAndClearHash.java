package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public interface ClearParametersAndClearHash {
	@NotNull public ClearParameters clearParameters();
	@NotEmpty public byte[] clearHash();
}
