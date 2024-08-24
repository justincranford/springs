package com.github.justincranford.springs.util.security.hashes.encoder.model;

import org.springframework.security.crypto.password.PasswordEncoder;

public class KeyEncoder extends Encoder {
	public KeyEncoder(final String idForEncode, final PasswordEncoder encoder) {
		super(idForEncode, encoder);
	}
}
