package com.github.justincranford.springs.util.security.hashes.encoder;

import org.springframework.security.crypto.password.PasswordEncoder;

public class ValueEncoder extends Encoder {
	public ValueEncoder(final PasswordEncoder encoder) {
		super(encoder);
	}
}
