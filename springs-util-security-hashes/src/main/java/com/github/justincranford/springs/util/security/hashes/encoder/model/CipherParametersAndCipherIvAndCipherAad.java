package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record CipherParametersAndCipherIvAndCipherAad(
	@NotNull CipherParameters cipherParameters,
	@NotEmpty byte[] cipherIvBytes,
	@NotEmpty byte[] cipherAadBytes
) {
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(this.cipherIvBytes, this.cipherAadBytes, this.cipherParameters().canonicalBytes());
	}
}
