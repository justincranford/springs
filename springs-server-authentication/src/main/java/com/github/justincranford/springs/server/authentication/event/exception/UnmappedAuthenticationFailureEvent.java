package com.github.justincranford.springs.server.authentication.event.exception;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

public final class UnmappedAuthenticationFailureEvent extends AbstractAuthenticationFailureEvent {
    public UnmappedAuthenticationFailureEvent(Authentication authentication, AuthenticationException exception) {
        super(authentication, exception);
    }
}
