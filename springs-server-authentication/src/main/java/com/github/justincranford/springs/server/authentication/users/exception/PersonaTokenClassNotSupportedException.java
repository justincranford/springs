package com.github.justincranford.springs.server.authentication.users.exception;

import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonaTokenClassNotSupportedException extends BadCredentialsException {
	@Serial
	private static final long serialVersionUID = 1L;

	public PersonaTokenClassNotSupportedException(String msg) {
		super(msg);
	}
	public PersonaTokenClassNotSupportedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
