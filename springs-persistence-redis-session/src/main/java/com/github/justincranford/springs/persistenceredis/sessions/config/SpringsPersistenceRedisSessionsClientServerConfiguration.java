package com.github.justincranford.springs.persistenceredis.sessions.config;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.github.justincranford.springs.persistenceredis.sessions.generator.CustomSessionIdGenerator;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers.ContainerDescriptor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.jackson2.SimpleGrantedAuthorityMixin;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.SpringSessionRedisConnectionFactory;
import org.springframework.session.data.redis.config.annotation.web.http.RedisHttpSessionConfiguration;
import redis.embedded.RedisServer;

import java.io.IOException;
import java.time.Duration;
import java.util.List;

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
@Configuration
@Slf4j
public class SpringsPersistenceRedisSessionsClientServerConfiguration {
    @Autowired
    private RedisProperties redisProperties;

    @Bean(initMethod="start",destroyMethod="stop")
    public RedisServer redisServerEmbedded(final Environment environment) throws IOException {
        List<ContainerDescriptor> running = BootstrapTestContainers.running(environment, "redis");
        if ((running != null) && (!running.isEmpty())) {
            log.info("Skipping embedded redis server. Will use running redis container(s): {}", running);
            return null;
        }
        final String host = this.redisProperties.getHost();
        final Integer port = this.redisProperties.getPort();
        if ((!(host.equals("localhost"))) && (!(host.equals("127.0.0.1"))) && (!(host.equals("::1")))) {
            throw new RuntimeException("Wrong host for creating embedded redis server, host: " + host + ", port: " + port);
        }
        log.trace("Creating embedded redis server, host: {}, port: {}", host, port);
        final RedisServer redisServer = new RedisServer(port);
        log.info("Created embedded redis server, host: {}, port: {}", host, port);
        if (!redisServer.isActive()) {
            redisServer.start();
            log.info("Started embedded redis server, host: {}, port: {}", host, port);
        }
        return redisServer;
    }

    /** @see org.springframework.boot.autoconfigure.session.RedisSessionConfiguration */
    @Bean
    public RedisSessionRepository redisSessionRepository(final RedisTemplate<String, Object> sessionRedisTemplate) {
        return new RedisSessionRepository(sessionRedisTemplate);
    }

    @Bean
    public RedisTemplate<String, Object> sessionRedisTemplate(
        final LettuceConnectionFactory redisConnectionFactory,
        final RedisSerializer<Object> springSessionDefaultRedisSerializer
    ) {
        final StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();
        final RedisTemplate<String, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(stringRedisSerializer);
        redisTemplate.setHashKeySerializer(stringRedisSerializer);
        redisTemplate.setValueSerializer(springSessionDefaultRedisSerializer);
        redisTemplate.setHashValueSerializer(springSessionDefaultRedisSerializer);
        redisTemplate.setDefaultSerializer(springSessionDefaultRedisSerializer);
        log.info("redisTemplate: {}", redisTemplate);
        return redisTemplate;
    }
    @Bean
    public RedisHttpSessionConfiguration redisHttpSessionConfiguration(
        @SpringSessionRedisConnectionFactory ObjectProvider<RedisConnectionFactory> springSessionRedisConnectionFactory,
        final ObjectMapper springSessionDefaultRedisSerializer,
        final RedisConnectionFactory redisConnectionFactory
    ) {
        final RedisHttpSessionConfiguration config = new RedisHttpSessionConfiguration();
        config.setSessionIdGenerator(new CustomSessionIdGenerator());
        config.setMaxInactiveInterval(Duration.ofSeconds(7));
        config.setRedisNamespace("justin:cranford");
        config.setDefaultRedisSerializer(GenericJackson2JsonRedisSerializer.builder().objectMapper(springSessionDefaultRedisSerializer).build());
        final ObjectProvider<RedisConnectionFactory> objectProvider = new ObjectProvider<>() {
            @Override
            public RedisConnectionFactory getObject() throws BeansException {
                return redisConnectionFactory;
            }

        };
        config.setRedisConnectionFactory(objectProvider, objectProvider);
        return config;
    }

    @Bean(name="springSessionDefaultRedisSerializer")
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        final ObjectMapper objectMapper = SpringsUtilJsonConfiguration.newObjectMapper();
        objectMapper.activateDefaultTyping(
            LaissezFaireSubTypeValidator.instance,
            ObjectMapper.DefaultTyping.NON_FINAL,
            JsonTypeInfo.As.PROPERTY
        );
        objectMapper.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);

        return GenericJackson2JsonRedisSerializer.builder().objectMapper(objectMapper).build();
    }

    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        final String host = this.redisProperties.getHost();
        final int port = this.redisProperties.getPort();
        log.info("Creating redis client, host: {}, port: {}", host, port);
        return new LettuceConnectionFactory(host, port);
    }

}
