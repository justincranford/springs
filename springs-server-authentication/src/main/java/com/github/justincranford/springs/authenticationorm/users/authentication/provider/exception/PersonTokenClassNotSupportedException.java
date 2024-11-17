package com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception;

import org.springframework.security.authentication.BadCredentialsException;

import java.io.Serial;

@SuppressWarnings({"unused"})
public class PersonTokenClassNotSupportedException extends BadCredentialsException {
    @Serial
    private static final long serialVersionUID = 1L;

    public PersonTokenClassNotSupportedException(String msg) {
        super(msg);
    }

    public PersonTokenClassNotSupportedException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
