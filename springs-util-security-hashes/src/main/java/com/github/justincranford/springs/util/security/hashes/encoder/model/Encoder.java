package com.github.justincranford.springs.util.security.hashes.encoder.model;

import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public abstract class Encoder implements PasswordEncoder {
	private final PasswordEncoder encoder;
	@Override
	public String encode(final CharSequence rawPassword) {
		return this.encoder.encode(rawPassword);
	}
	@Override
	public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
		return this.encoder.matches(rawPassword, encodedPassword);
	}
}
