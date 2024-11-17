package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonTokenNullNotAllowedException extends BadCredentialsException {
    @Serial
    private static final long serialVersionUID = 1L;

    public PersonTokenNullNotAllowedException(String msg) {
        super(msg);
    }

    public PersonTokenNullNotAllowedException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
