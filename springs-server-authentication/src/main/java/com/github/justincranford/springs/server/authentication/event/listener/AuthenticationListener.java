package com.github.justincranford.springs.server.authentication.event.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationListener {
    @EventListener
    public void onSuccess(final AuthenticationSuccessEvent success) {
        log.info("AuthenticationListener.onSuccess: {}", success);
    }

    @EventListener
    public void onFailure(final AbstractAuthenticationFailureEvent failure) {
        log.info("AuthenticationListener.onFailure: {}", failure);
    }
}
