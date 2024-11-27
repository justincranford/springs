package com.github.justincranford.springs.persistenceorm.users.persona.exception;

import com.github.justincranford.springs.util.basic.exception.CustomAuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonaEmailNotFoundException extends UsernameNotFoundException implements CustomAuthenticationException {
	@Serial
	private static final long serialVersionUID = 1L;
	public PersonaEmailNotFoundException(String msg) {
		super(msg);
	}
	public PersonaEmailNotFoundException(String msg, Throwable cause) {
		super(msg, cause);
	}
}
