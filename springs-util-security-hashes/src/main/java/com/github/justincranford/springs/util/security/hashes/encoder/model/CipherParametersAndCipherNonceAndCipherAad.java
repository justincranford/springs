package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record CipherParametersAndCipherNonceAndCipherAad(
	@NotNull CipherParameters cipherParameters,
	@NotEmpty byte[] cipherNonceBytes,
	@NotEmpty byte[] cipherAadBytes
) {
	public byte[] canonicalEncodedBytes() {
		return ArrayUtil.concat(this.cipherNonceBytes, this.cipherAadBytes, this.cipherParameters().canonicalBytes());
	}
}
