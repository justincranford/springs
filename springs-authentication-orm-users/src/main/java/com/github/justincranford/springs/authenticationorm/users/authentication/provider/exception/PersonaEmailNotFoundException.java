package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class PersonaEmailNotFoundException extends UsernameNotFoundException {
	private static final long serialVersionUID = 1L;
	public PersonaEmailNotFoundException(String msg) {
		super(msg);
	}
	public PersonaEmailNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
