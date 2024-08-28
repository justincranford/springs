package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Null;

public interface SecretParameters {
	@Null public byte[] context();
	@NotEmpty public CharSequence rawInput();
}
