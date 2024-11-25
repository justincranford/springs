package com.github.justincranford.springs.server.authentication.user.exception;

import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonaTokenNullNotAllowedException extends BadCredentialsException {
	@Serial
	private static final long serialVersionUID = 1L;

	public PersonaTokenNullNotAllowedException(String msg) {
		super(msg);
	}
	public PersonaTokenNullNotAllowedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
