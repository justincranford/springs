package com.github.justincranford.springs.persistenceorm.base;

import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.persistenceorm.base.properties.SpringsPersistenceOrmBaseProperties;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(classes={SpringsPersistenceOrmBaseConfiguration.class,AbstractIT.AbstractITConfiguration.class})
@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
public class AbstractIT {
    @Autowired
	private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
	@Autowired
	private SpringsPersistenceOrmBaseProperties springsPersistenceOrmBaseProperties;

    @Configuration
	@EnableAutoConfiguration
	public static class AbstractITConfiguration {
    	// do nothing
    }

    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("bootstrap.testcontainers.mode",                 () -> "preferred");
        registry.add("bootstrap.testcontainers.containers.postgres1", () -> "postgres:16.3");
    }
}
