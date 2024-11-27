package com.github.justincranford.springs.server.authentication.client.exception;

import com.github.justincranford.springs.util.basic.exception.CustomAuthenticationException;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class ClientTokenClassNotSupportedException extends BadCredentialsException implements CustomAuthenticationException {
	@Serial
	private static final long serialVersionUID = 1L;

	public ClientTokenClassNotSupportedException(String msg) {
		super(msg);
	}
	public ClientTokenClassNotSupportedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
