package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonPasswordBlankNotAllowedException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonPasswordBlankNotAllowedException(String msg) {
		super(msg);
	}
	public PersonPasswordBlankNotAllowedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
