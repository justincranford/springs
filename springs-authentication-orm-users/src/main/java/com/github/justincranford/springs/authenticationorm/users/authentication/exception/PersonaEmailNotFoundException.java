package com.github.justincranford.springs.authenticationorm.users.authentication.exception;

import org.springframework.security.core.AuthenticationException;

public class PersonaEmailNotFoundException extends AuthenticationException {
	private static final long serialVersionUID = 1L;
	public PersonaEmailNotFoundException(String msg) {
		super(msg);
	}
	public PersonaEmailNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
