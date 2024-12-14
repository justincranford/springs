package com.github.justincranford.springs.server.authentication.anonymous;

import org.springframework.security.core.AuthenticationException;

public class AnonymousAuthenticationException extends AuthenticationException {
    public AnonymousAuthenticationException(final String msg) {
        super(msg);
    }
}
