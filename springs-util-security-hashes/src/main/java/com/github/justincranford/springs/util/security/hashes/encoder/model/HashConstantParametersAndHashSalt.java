package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record HashConstantParametersAndHashSalt(
	@NotNull HashConstantParameters hashParameters,
	@NotEmpty byte[] hashSaltBytes
) {
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(this.hashSaltBytes, this.hashParameters().canonicalBytes());
	}
}
