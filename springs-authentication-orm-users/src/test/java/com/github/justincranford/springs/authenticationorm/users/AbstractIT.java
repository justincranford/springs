package com.github.justincranford.springs.authenticationorm.users;

import java.util.List;

import org.hibernate.dialect.PostgreSQLDialect;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.containers.PostgreSQLContainer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonaEmailPasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.config.SpringsAuthenticationOrmUsersConfiguration;
import com.github.justincranford.springs.authenticationorm.users.session.SessionOrmRepository;
import com.github.justincranford.springs.persistenceorm.base.properties.SpringsPersistenceOrmBaseProperties;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;
import com.github.justincranford.springs.service.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.certs.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.certs.server.TlsInitializer;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    classes = {
		SpringsAuthenticationOrmUsersConfiguration.class,
        SpringsUtilTestContainers.class
    }
)
//@AutoConfigureMockMvc
@ContextConfiguration(
	initializers={TlsInitializer.class}
)
//@EnableAutoConfiguration
//@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
//@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
//@Observed
@SuppressWarnings("nls")
public class AbstractIT {
	@LocalServerPort
	private long localServerPort;
	@Autowired
    private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
    @Autowired
    private PersonOrmRepository personOrmRepository;
    @Autowired
    private PersonaOrmRepository personaOrmRepository;
    @Autowired
    private SessionOrmRepository sessionOrmRepository;
    @Autowired
    private SpringsPersistenceOrmBaseProperties springsPersistenceOrmBaseProperties;
    @SpyBean
    private PersonaEmailPasswordAuthenticationProvider personaEmailPasswordAuthenticationProvider;
    @SpyBean
    private PersonUsernamePasswordAuthenticationProvider personUsernamePasswordAuthenticationProvider;
    @Autowired
    private HttpSecurity http;

	@Value("${server.address}")
	private String serverAddress;

	@Autowired
	private WebServerApplicationContext webServerApplicationContext;

	/**
	 * @see SpringsUtilHttpClientConfiguration#httpRestTemplate
	 */
	@Autowired
	@Qualifier("httpRestTemplate")
	private RestTemplate httpRestTemplate;

	/**
	 * @see SpringsUtilHttpsClientsConfiguration#mtlsRestTemplate
	 */
	@Autowired(required=false)
	@Qualifier("mtlsRestTemplate")
	private RestTemplate mtlsRestTemplate;

	/**
	 * @see SpringsUtilHttpsClientsConfiguration#stlsRestTemplate
	 */
	@Autowired(required=false)
	@Qualifier("stlsRestTemplate")
	private RestTemplate stlsRestTemplate;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private String httpBaseUrl;

	@Autowired
	private String httpsBaseUrl;

	@BeforeAll
    private static void beforeAll() {
        SpringsUtilTestContainers.startContainers(List.of(SpringsUtilTestContainers.POSTGRESQL));
    }

    @SuppressWarnings("resource")
	@DynamicPropertySource
    public static void postgresqlContainerProperties(final DynamicPropertyRegistry registry) {
		final PostgreSQLContainer<?> instance = SpringsUtilTestContainers.POSTGRESQL.getInstance();
		if (instance.isRunning()) {
			log.info("Setting dynamic properties from SpringsUtilTestContainers.POSTGRESQL");
	        registry.add("spring.jpa.properties.hibernate.dialect", () -> PostgreSQLDialect.class.getCanonicalName());
	        registry.add("spring.datasource.url",                   () -> instance.getJdbcUrl());
	        registry.add("spring.datasource.username",              () -> instance.getUsername());
	        registry.add("spring.datasource.password",              () -> instance.getPassword());
		} else {
			log.info("Using static properties");
		}
    }
}
