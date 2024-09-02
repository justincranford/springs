package com.github.justincranford.springs.util.security.hashes.encoder.model;

import com.github.justincranford.springs.util.basic.ArrayUtil;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record ParametersAndSalt(@NotNull Parameters parameters, @NotEmpty byte[] saltBytes) {
	public byte[] canonicalEncodedBytes() {
		return ArrayUtil.concat(this.saltBytes, this.parameters().canonicalEncodedBytes());
	}
}
