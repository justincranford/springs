package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.Null;

public interface HashPepper {
	@Null public Pepper pepper();

	default public int outputBytesLength(final int fallbackLength) {
		return (this.pepper() != null) ? this.pepper().mac().outputBytesLen() : fallbackLength;
	}
}
