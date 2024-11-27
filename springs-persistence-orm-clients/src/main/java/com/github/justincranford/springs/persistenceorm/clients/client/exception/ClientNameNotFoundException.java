package com.github.justincranford.springs.persistenceorm.clients.client.exception;

import com.github.justincranford.springs.util.basic.exception.CustomAuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class ClientNameNotFoundException extends UsernameNotFoundException implements CustomAuthenticationException {
	@Serial
	private static final long serialVersionUID = 1L;
	public ClientNameNotFoundException(String msg) {
		super(msg);
	}
	public ClientNameNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
