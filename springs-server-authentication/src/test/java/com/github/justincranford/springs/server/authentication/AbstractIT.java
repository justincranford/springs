package com.github.justincranford.springs.server.authentication;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.properties.SpringsPersistenceOrmBaseProperties;
import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties;
import com.github.justincranford.springs.persistenceredis.sessions.config.SpringsPersistenceRedisSessionsClientServerConfiguration;
import com.github.justincranford.springs.server.authentication.client.provider.ClientNameSecretAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.config.SpringsServerAuthenticationConfiguration;
import com.github.justincranford.springs.server.authentication.event.listener.AuthenticationListener;
import com.github.justincranford.springs.server.authentication.event.listener.LoginAttemptsLogger;
import com.github.justincranford.springs.server.authentication.event.listener.SessionEventListeners;
import com.github.justincranford.springs.server.authentication.user.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.user.provider.PersonaEmailPasswordAuthenticationProvider;
import com.github.justincranford.springs.util.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilTlsClientsConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.BootstrapTlsApplicationContextInitializer;
import com.github.justincranford.springs.util.json.PrettyJson;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisSessionRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    classes = {
		SpringsServerAuthenticationConfiguration.class
    }
)
@ContextConfiguration(
	initializers={
		BootstrapTlsApplicationContextInitializer.class,
		BootstrapTestContainersApplicationContextInitializer.class
	}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
public class AbstractIT {
	@Autowired
	@SuppressWarnings({"rawtypes"})
	private SessionRepository sessionRepository;
	@Autowired
	private RedisSessionRepository redisSessionRepository;
	@Autowired
    private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
	@Autowired
	private ApplicationEventPublisher applicationEventPublisher;
	@Autowired
	private AuthenticationEventPublisher authenticationEventPublisher;
	@Autowired
    private PersonOrmRepository personOrmRepository;
    @Autowired
    private PersonaOrmRepository personaOrmRepository;
    @Autowired
    private SpringsPersistenceOrmBaseProperties springsPersistenceOrmBaseProperties;
    @Autowired
    private SpringsPersistenceOrmUsersPeopleProperties springsPersistenceOrmUsersPeopleProperties;
	@Autowired
	private SpringsPersistenceOrmClientsClientProperties springsPersistenceOrmClientsClientProperties;
    @SpyBean
    private PersonaEmailPasswordAuthenticationProvider personaEmailPasswordAuthenticationProvider;
    @SpyBean
    private PersonUsernamePasswordAuthenticationProvider personUsernamePasswordAuthenticationProvider;
	@SpyBean
	private ClientNameSecretAuthenticationProvider clientNameSecretAuthenticationProvider;
	@SpyBean
	private AuthenticationListener authenticationListener;
	@SpyBean
	private LoginAttemptsLogger loginAttemptsLogger;
	@SpyBean
	private SessionEventListeners sessionEventListeners;

    @Autowired
    private HttpSecurity http;
	@Autowired
	private WebServerApplicationContext webServerApplicationContext;
	@Autowired
	private SslBundles sslBundles;

	@Autowired
	@Qualifier("httpRestTemplate")
	private RestTemplate httpRestTemplate; /** @see SpringsUtilHttpClientConfiguration#httpRestTemplate */

	@Autowired(required=false)
	@Qualifier("mtlsRestTemplate")
	private RestTemplate mtlsRestTemplate; /** @see SpringsUtilHttpsClientsConfiguration#mtlsRestTemplate */

	@Autowired(required=false)
	@Qualifier("stlsRestTemplate")
	private RestTemplate stlsRestTemplate; /** @see SpringsUtilHttpsClientsConfiguration#stlsRestTemplate */

	@Autowired(required=false)
	@Qualifier("ptlsRestTemplate")
	private RestTemplate ptlsRestTemplate; /** @see SpringsUtilHttpsClientsConfiguration#ptlsRestTemplate */

	@Autowired(required=false)
	@Qualifier("stlsSslContext")
	private SSLContext stlsSslContext; /** @see SpringsUtilTlsClientsConfiguration#stlsSslContext */

	@Autowired(required=false)
	@Qualifier("mtlsSslContext")
	private SSLContext mtlsSslContext; /** @see SpringsUtilTlsClientsConfiguration#mtlsSslContext */

	@Autowired(required=false)
	@Qualifier("ptlsSslContext")
	private SSLContext ptlsSslContext; /** @see SpringsUtilTlsClientsConfiguration#ptlsSslContext */

	/** @see com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration#objectMapper */
	@Autowired
	private ObjectMapper objectMapper;

	/** @see SpringsPersistenceRedisSessionsClientServerConfiguration#springSessionDefaultObjectMapper */
	@Qualifier("springSessionDefaultObjectMapper")
	@Autowired
	private ObjectMapper springSessionDefaultObjectMapper;

	/** @see com.github.justincranford.springs.persistenceredis.sessions.config.SpringsPersistenceRedisSessionsClientServerConfiguration#springSessionDefaultRedisSerializer */
	@Autowired
	public RedisSerializer<Object> springSessionDefaultRedisSerializer;

	@Autowired
	private PrettyJson prettyJson;

	@Autowired
	private String httpBaseUrl;

	@Autowired
	private String httpsBaseUrl;

	@Autowired
	private String httpsPskBaseUrl;

	@DynamicPropertySource
	static void properties(final DynamicPropertyRegistry registry) {
		registry.add("bootstrap.testcontainers.mode",                 () -> "preferred");
		registry.add("bootstrap.testcontainers.containers.redis1",    () -> "redis:7.4.1");
		registry.add("bootstrap.testcontainers.containers.postgres1", () -> "postgres:17.2");
	}
}
