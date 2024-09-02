package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record HashParametersAndHashSaltAndHash(
	@NotNull HashParametersAndHashSalt hashParametersAndHashSalt,
	@NotEmpty byte[] hashBytes
) { }
