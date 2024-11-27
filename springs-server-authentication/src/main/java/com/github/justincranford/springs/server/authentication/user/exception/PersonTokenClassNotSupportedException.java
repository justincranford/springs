package com.github.justincranford.springs.server.authentication.user.exception;

import com.github.justincranford.springs.util.basic.exception.CustomAuthenticationException;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonTokenClassNotSupportedException extends BadCredentialsException implements CustomAuthenticationException {
	@Serial
	private static final long serialVersionUID = 1L;

	public PersonTokenClassNotSupportedException(String msg) {
		super(msg);
	}
	public PersonTokenClassNotSupportedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
