package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonTokenNullNotAllowedException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonTokenNullNotAllowedException(String msg) {
		super(msg);
	}
	public PersonTokenNullNotAllowedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
