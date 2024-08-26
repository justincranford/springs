package com.github.justincranford.springs.util.security.hashes.encoder.config.model;

import org.springframework.security.crypto.password.PasswordEncoder;

public class ValueEncoder extends Encoder {
	public ValueEncoder(final String idForEncode, final PasswordEncoder encoder) {
		super(idForEncode, encoder);
	}
}
