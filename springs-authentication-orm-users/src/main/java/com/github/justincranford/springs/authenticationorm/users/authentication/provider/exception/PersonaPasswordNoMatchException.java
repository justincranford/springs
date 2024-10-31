package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonaPasswordNoMatchException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonaPasswordNoMatchException(String msg) {
		super(msg);
	}
	public PersonaPasswordNoMatchException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
