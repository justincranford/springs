package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotNull;

public record HashParameters(
	@NotNull HashConstants hashConstants,
	@NotNull HashVariables hashVariables
) {
	public byte[] canonicalBytes() {
		return ArrayUtil.concat(this.hashVariables().canonicalBytes(), this.hashConstants().canonicalBytes());
	}
}
