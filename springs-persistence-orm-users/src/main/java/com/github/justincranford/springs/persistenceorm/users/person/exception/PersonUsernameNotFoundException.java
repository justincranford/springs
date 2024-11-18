package com.github.justincranford.springs.persistenceorm.users.person.exception;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonUsernameNotFoundException extends UsernameNotFoundException {
	@Serial
	private static final long serialVersionUID = 1L;
	public PersonUsernameNotFoundException(String msg) {
		super(msg);
	}
	public PersonUsernameNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
