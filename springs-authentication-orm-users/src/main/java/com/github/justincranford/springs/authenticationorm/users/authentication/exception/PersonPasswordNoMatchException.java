package com.github.justincranford.springs.authenticationorm.users.authentication.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonPasswordNoMatchException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonPasswordNoMatchException(String msg) {
		super(msg);
	}
	public PersonPasswordNoMatchException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
