package com.github.justincranford.springs.persistenceredis.sessions.config;

import com.github.justincranford.springs.persistenceredis.properties.RedisProperties;
import com.github.justincranford.springs.persistenceredis.sessions.generator.CustomSessionIdGenerator;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers.ContainerDescriptor;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import redis.embedded.RedisServer;

import java.io.IOException;
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
@Import(SpringsPersistenceRedisSessionsPersistenceConfiguration.ExtraConfiguration.class)
@EnableRedisHttpSession
@Slf4j
public class SpringsPersistenceRedisSessionsPersistenceConfiguration {
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

    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        final String host = this.redisProperties.getHost();
        final Integer port = this.redisProperties.getPort();
        log.info("Creating redis client, host: {}, port: {}", host, port);
        return new LettuceConnectionFactory(host, port);
    }

    @Bean
    public RedisTemplate<String, Object> redisTemplate(final LettuceConnectionFactory redisConnectionFactory) {
        final RedisTemplate<String, Object> template = new RedisTemplate<>();
        template.setConnectionFactory(redisConnectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new GenericJackson2JsonRedisSerializer());
        return template;
    }

    @Configuration
    public static class ExtraConfiguration {
        @Autowired
        private RedisSessionRepository redisSessionRepository;

        @PostConstruct
        public void postConstruct() {
            log.info("Add CustomSessionIdGenerator to sessionRepository: {}", this.redisSessionRepository.getClass().getCanonicalName());
            this.redisSessionRepository.setSessionIdGenerator(new CustomSessionIdGenerator());
        }

//        @Bean
//        public SessionRepositoryCustomizer<RedisIndexedSessionRepository> redisSessionRepositoryCustomizer() {
//            return redisSessionRepositoryCustomizer -> {
//                redisSessionRepositoryCustomizer.setSessionIdGenerator(new CustomSessionIdGenerator());
//                redisSessionRepositoryCustomizer.setDefaultMaxInactiveInterval(Duration.ofMinutes(60)); // 1 hour
//                redisSessionRepositoryCustomizer.setRedisKeyNamespace("myapp:sessions");
//            };
//        }
    }
}
