package com.github.justincranford.springs.util.security.hashes.encoder.model;

import java.util.function.BiFunction;
import java.util.function.Function;

import org.springframework.security.crypto.password.PasswordEncoder;

public abstract class IocEncoder implements PasswordEncoder {
	protected Function<CharSequence, String> encode;
	protected BiFunction<CharSequence, String, Boolean> matches;
	protected Function<String, Boolean> upgradeEncoding;

	@Override
	public String encode(final CharSequence rawPassword) {
		return this.encode.apply(rawPassword);
	}

	@Override
	public boolean matches(final CharSequence rawPassword, final String encodedPassword) {
		return this.matches.apply(rawPassword, encodedPassword).booleanValue();
	}

	@Override
	public boolean upgradeEncoding(final String encodedPassword) {
		return this.upgradeEncoding.apply(encodedPassword).booleanValue();
	}
}
