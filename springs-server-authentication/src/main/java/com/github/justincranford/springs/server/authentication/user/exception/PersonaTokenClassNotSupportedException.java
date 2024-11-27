package com.github.justincranford.springs.server.authentication.user.exception;

import com.github.justincranford.springs.util.basic.exception.CustomAuthenticationException;
import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonaTokenClassNotSupportedException extends BadCredentialsException implements CustomAuthenticationException {
	@Serial
	private static final long serialVersionUID = 1L;

	public PersonaTokenClassNotSupportedException(String msg) {
		super(msg);
	}
	public PersonaTokenClassNotSupportedException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
