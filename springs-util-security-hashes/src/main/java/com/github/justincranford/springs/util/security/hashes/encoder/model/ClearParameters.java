package com.github.justincranford.springs.util.security.hashes.encoder.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Null;

public interface ClearParameters {
	@Null public byte[] context();
	@NotEmpty public byte[] salt();
}
