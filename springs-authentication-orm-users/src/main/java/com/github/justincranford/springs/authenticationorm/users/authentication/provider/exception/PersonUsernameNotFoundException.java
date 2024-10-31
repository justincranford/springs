package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.core.AuthenticationException;

public class PersonUsernameNotFoundException extends AuthenticationException {
	private static final long serialVersionUID = 1L;
	public PersonUsernameNotFoundException(String msg) {
		super(msg);
	}
	public PersonUsernameNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
