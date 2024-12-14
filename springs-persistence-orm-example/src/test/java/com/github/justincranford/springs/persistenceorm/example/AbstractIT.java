package com.github.justincranford.springs.persistenceorm.example;

import com.github.justincranford.springs.persistenceorm.base.properties.SpringsPersistenceOrmBaseProperties;
import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.bushel.BushelOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.config.SpringsPersistenceOrmExampleConfiguration;
import com.github.justincranford.springs.persistenceorm.example.properties.SpringsPersistenceOrmExampleProperties;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
    classes = {
        SpringsPersistenceOrmExampleConfiguration.class
    }
)
@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
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
    private AppleOrmRepository appleOrmRepository;
    @Autowired
    private BushelOrmRepository bushelOrmRepository;
    @Autowired
    private SpringsPersistenceOrmExampleProperties springsPersistenceOrmExampleProperties;
    @Autowired
    private SpringsPersistenceOrmBaseProperties springsPersistenceOrmBaseProperties;

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("bootstrap.testcontainers.mode",                 () -> "preferred");
        registry.add("bootstrap.testcontainers.containers.postgres1", () -> "postgres:17.2");
    }
}
