package com.github.justincranford.springs.persistenceredis.sessions.config;

import com.github.justincranford.springs.persistenceredis.properties.RedisProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;
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
 * @see org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession
 * @see org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration
 * <p/>
 * @see org.springframework.session.web.http.SessionRepositoryFilter
// * @see org.springframework.session.data.redis.RedisIndexedSessionRepository.RedisSession;
 * @see org.springframework.session.data.redis.RedisSessionRepository
 * @see org.springframework.session.data.redis.RedisIndexedSessionRepository
 * @see org.springframework.data.redis.connection.RedisConnectionFactory
 * @see org.springframework.data.redis.core.RedisTemplate
 * @see org.springframework.session.SessionIdGenerator
 * @see org.springframework.session.UuidSessionIdGenerator
// * @see org.springframework.session.data.redis.RedisSessionExpirationPolicy
 * @see org.springframework.session.data.redis.RedisSessionMapper
// * @see org.springframework.session.data.redis.SortedSetReactiveRedisSessionExpirationStore
 */
@Configuration(proxyBeanMethods = false)
@EnableSpringHttpSession
@EnableRedisHttpSession
@Slf4j
public class SpringsPersistenceRedisSessionsPersistenceConfiguration {
    @Autowired
    private RedisProperties redisProperties;

    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        log.info("Creating bean LettuceConnectionFactory for connecting to Redis at {}:{}", this.redisProperties.getHost(), this.redisProperties.getPort());
        return new LettuceConnectionFactory(this.redisProperties.getHost(), this.redisProperties.getPort());
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(final LettuceConnectionFactory redisConnectionFactory) {
        final RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        return template;
    }
}
