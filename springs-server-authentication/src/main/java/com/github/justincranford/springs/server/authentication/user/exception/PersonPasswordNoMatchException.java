package com.github.justincranford.springs.server.authentication.user.exception;

import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonPasswordNoMatchException extends BadCredentialsException {
	@Serial
	private static final long serialVersionUID = 1L;

	public PersonPasswordNoMatchException(String msg) {
		super(msg);
	}
	public PersonPasswordNoMatchException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
