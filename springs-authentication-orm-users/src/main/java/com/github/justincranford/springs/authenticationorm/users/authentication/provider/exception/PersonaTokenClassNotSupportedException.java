package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonaTokenClassNotSupportedException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonaTokenClassNotSupportedException(String msg) {
		super(msg);
	}
	public PersonaTokenClassNotSupportedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
