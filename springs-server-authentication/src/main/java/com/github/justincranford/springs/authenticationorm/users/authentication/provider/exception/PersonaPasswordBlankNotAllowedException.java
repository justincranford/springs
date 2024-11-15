package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonaPasswordBlankNotAllowedException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonaPasswordBlankNotAllowedException(String msg) {
		super(msg);
	}
	public PersonaPasswordBlankNotAllowedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
