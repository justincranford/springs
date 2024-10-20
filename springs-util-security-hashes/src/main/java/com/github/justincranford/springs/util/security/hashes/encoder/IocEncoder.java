package com.github.justincranford.springs.util.security.hashes.encoder;

import java.util.function.BiFunction;
import java.util.function.Function;

import org.springframework.security.crypto.password.PasswordEncoder;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

public abstract class IocEncoder implements PasswordEncoder {
	protected Function<CharSequence, String> encode;
	protected BiFunction<CharSequence, String, Boolean> matches;
	protected Function<String, Boolean> upgradeEncoding;

	@Override
	@NotBlank public String encode(@NotNull final CharSequence rawPassword) {
		return this.encode.apply(rawPassword);
	}

	@Override
	public boolean matches(@NotNull final CharSequence rawPassword, @NotEmpty final String encodedPassword) {
		return this.matches.apply(rawPassword, encodedPassword).booleanValue();
	}

	@Override
	public boolean upgradeEncoding(@NotEmpty final String encodedPassword) {
		return this.upgradeEncoding.apply(encodedPassword).booleanValue();
	}
}
