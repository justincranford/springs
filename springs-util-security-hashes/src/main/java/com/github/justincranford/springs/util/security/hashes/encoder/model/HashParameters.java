package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotNull;

public record HashParameters(
	@NotNull HashConstantParameters hashConstantParameters,
	@NotNull HashVariableParameters hashVariableParameters
) {
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(this.hashVariableParameters().canonicalBytes(), this.hashConstantParameters().canonicalBytes());
	}
}
