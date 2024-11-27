package com.github.justincranford.springs.server.authentication.event.config;

import com.github.justincranford.springs.server.authentication.event.listener.AuthenticationListener;
import com.github.justincranford.springs.server.authentication.event.listener.LoginAttemptsLogger;
import com.github.justincranford.springs.server.authentication.event.listener.SessionEventListeners;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

/**
 * @see org.springframework.session.config.annotation.web.http.EnableSpringHttpSession
 * @see org.springframework.session.config.annotation.web.http.SpringHttpSessionConfiguration
 * <p/>
 * @see jakarta.servlet.ServletContext
 * @see jakarta.servlet.SessionCookieConfig
 * @see jakarta.servlet.http.HttpSessionListener
 * <p/>
 * @see org.springframework.session.web.http.SessionRepositoryFilter
 * @see org.springframework.session.Session
 * @see org.springframework.session.SessionRepository
 * @see org.springframework.session.events.SessionCreatedEvent
 * @see org.springframework.session.events.SessionDestroyedEvent
 * @see org.springframework.session.security.web.authentication.SpringSessionRememberMeServices
 * @see org.springframework.session.web.http.CookieHttpSessionIdResolver
 * @see org.springframework.session.web.http.CookieSerializer
 * @see org.springframework.session.web.http.DefaultCookieSerializer
 * @see org.springframework.session.web.http.HttpSessionIdResolver
 * @see org.springframework.session.web.http.SessionEventHttpSessionListenerAdapter
 * <p/>
 * <p/>
 * @see EnableRedisHttpSession
 * @see org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration
 * <p/>
 * @see org.springframework.session.web.http.SessionRepositoryFilter
 * @see RedisSessionRepository
 * @see org.springframework.session.data.redis.RedisIndexedSessionRepository
 * @see org.springframework.data.redis.connection.RedisConnectionFactory
 * @see RedisTemplate
 * @see org.springframework.session.SessionIdGenerator
 * @see org.springframework.session.UuidSessionIdGenerator
// * @see org.springframework.session.data.redis.RedisSessionExpirationPolicy
 * @see org.springframework.session.data.redis.RedisSessionMapper
// * @see org.springframework.session.data.redis.SortedSetReactiveRedisSessionExpirationStore
 */
@Configuration
@ComponentScan(basePackageClasses={
    SessionEventListeners.class, LoginAttemptsLogger.class, AuthenticationListener.class
})
@Slf4j
public class SpringsServerAuthenticationEventsConfiguration {
    @Bean
    public AuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        final DefaultAuthenticationEventPublisher authenticationEventPublisher = new DefaultAuthenticationEventPublisher(applicationEventPublisher);
        authenticationEventPublisher.setDefaultAuthenticationFailureEvent(AbstractAuthenticationFailureEvent.class);
        return authenticationEventPublisher;
    }

}
