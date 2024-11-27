package com.github.justincranford.springs.server.authentication.event.config;

import com.github.justincranford.springs.server.authentication.event.exception.UnmappedAuthenticationFailureEvent;
import com.github.justincranford.springs.server.authentication.event.listener.AuthenticationListener;
import com.github.justincranford.springs.server.authentication.event.listener.LoginAttemptsLogger;
import com.github.justincranford.springs.server.authentication.event.listener.SessionEventListeners;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;

@Configuration
@ComponentScan(basePackageClasses={
    AuthenticationListener.class, LoginAttemptsLogger.class, SessionEventListeners.class
})
@Slf4j
public class SpringsServerAuthenticationEventsConfiguration {
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(final ApplicationEventPublisher applicationEventPublisher) {
        final DefaultAuthenticationEventPublisher authenticationEventPublisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);
        authenticationEventPublisher.setDefaultAuthenticationFailureEvent(UnmappedAuthenticationFailureEvent.class);
        return authenticationEventPublisher;
    }
}
