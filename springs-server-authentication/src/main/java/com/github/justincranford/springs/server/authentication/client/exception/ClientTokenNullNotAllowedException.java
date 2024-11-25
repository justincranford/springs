package com.github.justincranford.springs.server.authentication.client.exception;

import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class ClientTokenNullNotAllowedException extends BadCredentialsException {
	@Serial
	private static final long serialVersionUID = 1L;

	public ClientTokenNullNotAllowedException(String msg) {
		super(msg);
	}
	public ClientTokenNullNotAllowedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
