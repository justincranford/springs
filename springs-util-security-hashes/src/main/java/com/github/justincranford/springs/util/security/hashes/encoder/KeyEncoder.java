package com.github.justincranford.springs.util.security.hashes.encoder;

import org.springframework.security.crypto.password.PasswordEncoder;

public class KeyEncoder extends Encoder {
	public KeyEncoder(final PasswordEncoder encoder) {
		super(encoder);
	}
}
