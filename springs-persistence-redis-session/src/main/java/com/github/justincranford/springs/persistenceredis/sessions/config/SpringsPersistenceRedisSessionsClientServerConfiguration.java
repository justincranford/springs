package com.github.justincranford.springs.persistenceredis.sessions.config;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.justincranford.springs.persistenceredis.sessions.generator.CustomSessionIdGenerator;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers.ContainerDescriptor;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.data.redis.RedisProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
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
@Import(SpringsPersistenceRedisSessionsClientServerConfiguration.ExtraConfiguration.class)
@EnableRedisHttpSession
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

    @Primary
    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        final String host = this.redisProperties.getHost();
        final int port = this.redisProperties.getPort();
        log.info("Creating redis client, host: {}, port: {}", host, port);
        final LettuceConnectionFactory lettuceConnectionFactory = new LettuceConnectionFactory(host, port);
//        lettuceConnectionFactory.setAutoStartup(false);
//        lettuceConnectionFactory.setEarlyStartup(false);
        return lettuceConnectionFactory;
    }

    @Bean(name="springSessionDefaultRedisSerializer")
    @Qualifier("thisOne")
    public RedisSerializer<Object> thisOne(final ObjectMapper objectMapperRedis) {
        return GenericJackson2JsonRedisSerializer.builder().objectMapper(objectMapperRedis).build();
    }

    @Bean
    @Qualifier("objectMapperRedis")
    public ObjectMapper objectMapperRedis() {
        return new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new Jdk8Module())
//                .setSerializationInclusion(JsonInclude.Include.NON_EMPTY) // WebAuthn RegistrationRequest.allowCredentials=null breaks JavaScript
            .enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
            .configure(SerializationFeature.INDENT_OUTPUT, true)
//                .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
//                .configure(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS, false)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
//                .activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.EVERYTHING, JsonTypeInfo.As.PROPERTY)
            ;
    }

    @Primary
    @Bean
    public RedisTemplate<Object, Object> sessionRedisTemplate(
        final LettuceConnectionFactory redisConnectionFactory,
        @Qualifier("thisOne") final RedisSerializer<Object> thisOne
    ) {
        final StringRedisSerializer stringRedisSerializer = new StringRedisSerializer();
        final RedisTemplate<Object, Object> redisTemplate = new RedisTemplate<>();
        redisTemplate.setConnectionFactory(redisConnectionFactory);
        redisTemplate.setKeySerializer(stringRedisSerializer);
        redisTemplate.setHashKeySerializer(stringRedisSerializer);
        redisTemplate.setValueSerializer(thisOne);
        redisTemplate.setHashValueSerializer(thisOne);
        redisTemplate.setDefaultSerializer(thisOne);
        log.info("redisTemplate: {}", redisTemplate);
        return redisTemplate;
    }

    @Configuration
    public static class ExtraConfiguration {
        @Autowired
        private RedisSessionRepository redisSessionRepository;

        @PostConstruct
        public void postConstruct() {
            log.info("Add CustomSessionIdGenerator to sessionRepository: {}", this.redisSessionRepository.getClass().getCanonicalName());
            this.redisSessionRepository.setSessionIdGenerator(new CustomSessionIdGenerator());
            this.redisSessionRepository.setDefaultMaxInactiveInterval(Duration.ofMinutes(60));
            this.redisSessionRepository.setRedisKeyNamespace("springs:sessions");
        }
    }
}
