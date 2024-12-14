package com.github.justincranford.springs.server.authentication.anonymous.event;

import com.github.justincranford.springs.server.authentication.anonymous.AnonymousAuthenticationException;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.core.Authentication;

@ToString
@Slf4j
public class AnonymousAuthenticationEvent extends AbstractAuthenticationFailureEvent {
    private final Object source;
    public AnonymousAuthenticationEvent(final Object _source, final Authentication authentication) {
        super(authentication, new AnonymousAuthenticationException("No authentication took place"));
        this.source = _source;
        log.trace("AnonymousAuthenticationEvent: {}", this);
    }
}
