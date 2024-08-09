package com.github.justincranford.springs.persistenceorm.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.bushel.BushelOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.config.SpringsPersistenceOrmExampleConfiguration;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes={SpringsPersistenceOrmExampleConfiguration.class,SpringsUtilTestContainers.class,AbstractIT.AbstractITConfiguration.class})
@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
@SuppressWarnings("static-method")
public class AbstractIT {
    @Autowired
	private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
    @Autowired
	private AppleOrmRepository appleOrmRepository;
	@Autowired
	private BushelOrmRepository bushelOrmRepository;

	@PostConstruct
	private void postConstruct() {
		SpringsUtilTestContainers.startAllContainers();
	}

    @Configuration
	@EnableAutoConfiguration
	public static class AbstractITConfiguration {
    	// do nothing
    }
}
