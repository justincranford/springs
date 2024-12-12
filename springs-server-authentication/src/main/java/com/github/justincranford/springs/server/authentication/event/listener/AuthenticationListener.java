package com.github.justincranford.springs.server.authentication.event.listener;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.web.authentication.session.SessionFixationProtectionEvent;
import org.springframework.security.web.authentication.switchuser.AuthenticationSwitchUserEvent;
import org.springframework.stereotype.Component;

@Component
@Slf4j
public class AuthenticationListener {
    @EventListener
    public void onInteractiveAuthenticationSuccessEvent(final InteractiveAuthenticationSuccessEvent login) {
        log.info("AuthenticationListener.onInteractiveSuccess: {}", login);
    }

    @EventListener
    public void onAuthenticationSuccessEvent(final AuthenticationSuccessEvent authenticationSuccessEvent) {
        log.info("AuthenticationListener.onSuccess: {}", authenticationSuccessEvent);
    }

    @EventListener
    public void onAbstractAuthenticationFailureEvent(final AbstractAuthenticationFailureEvent authenticationFailureEvent) {
        log.info("AuthenticationListener.onFailure: {}", authenticationFailureEvent);
    }

    @EventListener
    public void onLogoutSuccessEvent(final LogoutSuccessEvent logoutSuccessEvent) {
        log.info("AuthenticationListener.onLogout: {}", logoutSuccessEvent);
    }

    @EventListener
    public void onSessionFixationProtection(final SessionFixationProtectionEvent sessionFixationProtectionEvent) {
        log.info("AuthenticationListener.onSession: {}", sessionFixationProtectionEvent);
    }

    @EventListener
    public void onAuthenticationSwitchUserEvent(final AuthenticationSwitchUserEvent authenticationSwitchUserEvent) {
        log.info("AuthenticationListener.onSwitch: {}", authenticationSwitchUserEvent);
    }
}
