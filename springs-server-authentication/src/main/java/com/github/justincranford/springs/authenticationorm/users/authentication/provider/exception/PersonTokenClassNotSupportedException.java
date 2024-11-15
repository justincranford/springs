package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

public class PersonTokenClassNotSupportedException extends BadCredentialsException {
	private static final long serialVersionUID = 1L;

	public PersonTokenClassNotSupportedException(String msg) {
		super(msg);
	}
	public PersonTokenClassNotSupportedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
