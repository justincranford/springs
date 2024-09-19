package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public record Hash(
	@NotNull HashConstants hashConstants,
	@NotNull byte[] hashBytes
) {
	public static String encode(@NotEmpty final byte[] actualHashBytes, @NotNull final HashConstants hashConstants) {
		return hashConstants.encode(actualHashBytes);
	}

	public static Hash decode(@NotNull final String actualHashEncoded, @NotNull final HashConstants hashConstants) {
		return new Hash(hashConstants, hashConstants.decode(actualHashEncoded));
	}
}
