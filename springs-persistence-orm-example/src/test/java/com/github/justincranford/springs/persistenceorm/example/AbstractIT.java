package com.github.justincranford.springs.persistenceorm.example;

import java.util.List;

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
import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.bushel.BushelOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.config.SpringsPersistenceOrmExampleConfiguration;
import com.github.justincranford.springs.persistenceorm.example.properties.SpringsPersistenceOrmExampleProperties;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = {
        SpringsPersistenceOrmExampleConfiguration.class,
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
@SuppressWarnings("nls")
public class AbstractIT {
	@LocalServerPort
	private long localServerPort;
	@Autowired
    private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
    @Autowired
    private AppleOrmRepository appleOrmRepository;
    @Autowired
    private BushelOrmRepository bushelOrmRepository;
    @Autowired
    private SpringsPersistenceOrmExampleProperties springsPersistenceOrmExampleProperties;
    @Autowired
    private SpringsPersistenceOrmBaseProperties springsPersistenceOrmBaseProperties;

    @BeforeAll
    private static void beforeAll() {
        SpringsUtilTestContainers.startContainers(List.of(SpringsUtilTestContainers.POSTGRESQL));
    }

    @SuppressWarnings("resource")
	@DynamicPropertySource
    public static void postgresqlContainerProperties(final DynamicPropertyRegistry registry) {
		if (SpringsUtilTestContainers.POSTGRESQL.isRunning()) {
			log.info("Setting dynamic properties from SpringsUtilTestContainers.POSTGRESQL");
			final PostgreSQLContainer<?> postgresqlContainer = SpringsUtilTestContainers.POSTGRESQL.getInstance();
	        registry.add("spring.jpa.properties.hibernate.dialect", () -> PostgreSQLDialect.class.getCanonicalName());
	        registry.add("spring.datasource.url",                   () -> postgresqlContainer.getJdbcUrl());
	        registry.add("spring.datasource.username",              () -> postgresqlContainer.getUsername());
	        registry.add("spring.datasource.password",              () -> postgresqlContainer.getPassword());
		} else {
			log.info("Using static properties");
		}
    }
}
