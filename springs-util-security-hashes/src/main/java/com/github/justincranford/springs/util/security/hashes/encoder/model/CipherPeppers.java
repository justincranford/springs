package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;

public record CipherPeppers(
	@NotNull CipherPepperIv cipherSaltPepper,
	@Null    CipherPepperAad cipherAadPepper,
	@NotNull CipherPepperPreCipher cipherPreCipherPepper,
	@NotNull CipherPepperPostCipher cipherPostCipherPepper
) { }
