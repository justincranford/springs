package com.github.justincranford.springs.persistenceorm.sessions.service.exception;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class PersonUsernameNotFoundException extends UsernameNotFoundException {
	private static final long serialVersionUID = 1L;
	public PersonUsernameNotFoundException(String msg) {
		super(msg);
	}
	public PersonUsernameNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
