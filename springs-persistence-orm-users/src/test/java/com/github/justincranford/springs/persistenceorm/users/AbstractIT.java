package com.github.justincranford.springs.persistenceorm.users;

import java.util.List;

import com.github.justincranford.springs.persistenceorm.users.person.service.PersonPasswordUpgradeEncodingService;
import com.github.justincranford.springs.persistenceorm.users.person.service.PersonService;
import com.github.justincranford.springs.persistenceorm.users.persona.service.PersonaService;
import org.hibernate.dialect.PostgreSQLDialect;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;

import com.github.justincranford.springs.persistenceorm.base.properties.SpringsPersistenceOrmBaseProperties;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmUsersConfiguration;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties;
import com.github.justincranford.springs.util.json.config.PrettyJson;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = {
        SpringsPersistenceOrmUsersConfiguration.class,
        SpringsUtilTestContainers.class
    }
)
@EnableAutoConfiguration
//@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
public class AbstractIT {
	@LocalServerPort
	private long localServerPort;
	@Autowired
    private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
	@Autowired
	private PrettyJson prettyJson;
    @Autowired
    private PersonOrmRepository personOrmRepository;
    @Autowired
    private PersonaOrmRepository personaOrmRepository;
    @Autowired
    private SpringsPersistenceOrmBaseProperties springsPersistenceOrmBaseProperties;
    @Autowired
    private SpringsPersistenceOrmUsersPeopleProperties peopleProperties;
    @Autowired
    private PersonPasswordUpgradeEncodingService personPasswordUpgradeEncodingService;
    @Autowired
    private PersonService personService;
    @Autowired
    private PersonaService personaService;

    @BeforeAll
    public static void beforeAll() {
        SpringsUtilTestContainers.startContainers(List.of(SpringsUtilTestContainers.POSTGRESQL));
    }

	@DynamicPropertySource
    public static void postgresqlContainerProperties(final DynamicPropertyRegistry registry) {
		final PostgreSQLContainer<?> instance = SpringsUtilTestContainers.POSTGRESQL.getInstance();
		if (instance.isRunning()) {
			log.info("Setting dynamic properties from SpringsUtilTestContainers.POSTGRESQL");
	        registry.add("spring.jpa.properties.hibernate.dialect", PostgreSQLDialect.class::getCanonicalName);
	        registry.add("spring.datasource.url", instance::getJdbcUrl);
	        registry.add("spring.datasource.username", instance::getUsername);
	        registry.add("spring.datasource.password", instance::getPassword);
		} else {
			log.info("Using static properties");
		}
    }
}
