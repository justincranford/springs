package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record CipherParametersAndCipherNonceAndCipherAadAndCipher(
	@NotNull CipherParameters cipherParameters,
	@NotEmpty byte[] cipherNonceBytes,
	@NotEmpty byte[] cipherAadBytes,
	@NotEmpty byte[] hashBytes
) {
}
