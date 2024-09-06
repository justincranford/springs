package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public record CipherPeppers(
	@NotNull CipherIvPepper cipherSaltPepper,
	@Null    CipherAadPepper cipherAadPepper,
	@NotNull CipherPreCipherPepper cipherPreCipherPepper,
	@NotNull CipherPostCipherPepper cipherPostCipherPepper
) { }
