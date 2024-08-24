package com.github.justincranford.springs.util.security.hashes.encoder.model;

import org.springframework.security.crypto.password.PasswordEncoder;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.Accessors;

@RequiredArgsConstructor
@Getter
@Accessors(fluent = true)
public abstract class Encoder implements PasswordEncoder {
	private final String idForEncode;
	private final PasswordEncoder encoder;

	public String idForEncode() {
		return this.idForEncode;
	}
	@Override
	public String encode(final CharSequence rawPassword) {
		return this.encoder.encode(rawPassword);
	}
	@Override
	public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
		return this.encoder.matches(rawPassword, encodedPassword);
	}
}
