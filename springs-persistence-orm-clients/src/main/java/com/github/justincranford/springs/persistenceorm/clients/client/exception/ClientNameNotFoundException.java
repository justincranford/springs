package com.github.justincranford.springs.persistenceorm.clients.client.exception;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class ClientNameNotFoundException extends UsernameNotFoundException {
	@Serial
	private static final long serialVersionUID = 1L;
	public ClientNameNotFoundException(String msg) {
		super(msg);
	}
	public ClientNameNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
