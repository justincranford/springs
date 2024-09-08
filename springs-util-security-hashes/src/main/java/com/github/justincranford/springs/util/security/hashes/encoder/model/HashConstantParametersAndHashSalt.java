package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record HashConstantParametersAndHashSalt(
	@NotNull HashConstantParameters hashConstantParameters,
	@NotEmpty byte[] hashSaltBytes
) {
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(this.hashSaltBytes, this.hashConstantParameters().canonicalBytes());
	}
}
