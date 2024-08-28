package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;

public interface EncodeDecodeSeparators {
	@NotEmpty public String encodeParameters();
	@NotEmpty public String decodeParameters();
	@NotEmpty public String encodeHash();
	@NotEmpty public String decodeHash();
}
