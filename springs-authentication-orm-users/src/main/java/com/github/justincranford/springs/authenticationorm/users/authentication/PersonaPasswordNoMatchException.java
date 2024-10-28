package com.github.justincranford.springs.authenticationorm.users.authentication;

import org.springframework.security.core.AuthenticationException;

public class PersonaPasswordNoMatchException extends AuthenticationException {
	private static final long serialVersionUID = 1L;

	public PersonaPasswordNoMatchException(String msg) {
		super(msg);
	}
	public PersonaPasswordNoMatchException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
