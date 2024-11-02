package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonaTokenNullNotAllowedException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonaTokenNullNotAllowedException(String msg) {
		super(msg);
	}
	public PersonaTokenNullNotAllowedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
