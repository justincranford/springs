package com.github.justincranford.springs.persistenceorm.clients.client.exception;

import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class ClientClientNameNotFoundException extends UsernameNotFoundException {
	@Serial
	private static final long serialVersionUID = 1L;
	public ClientClientNameNotFoundException(String msg) {
		super(msg);
	}
	public ClientClientNameNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
