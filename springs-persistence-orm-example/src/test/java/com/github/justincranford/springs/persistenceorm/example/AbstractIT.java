package com.github.justincranford.springs.persistenceorm.example;

import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.bushel.BushelOrmRepository;
import com.github.justincranford.springs.persistenceorm.example.config.SpringsPersistenceOrmConfiguration;
import com.github.justincranford.springs.persistenceorm.example.properties.SpringsPersistenceOrmProperties;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(classes={SpringsPersistenceOrmConfiguration.class,SpringsUtilTestContainers.class,AbstractIT.AbstractITConfiguration.class})
@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings("nls")
@Observed
public class AbstractIT {
    @Autowired
	private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
	@Autowired
	private SpringsPersistenceOrmProperties springsPersistenceOrmProperties;
    @Autowired
	private AppleOrmRepository appleOrmRepository;
	@Autowired
	private BushelOrmRepository bushelOrmRepository;

	@PostConstruct
	private void postConstruct() {
		SpringsUtilTestContainers.startAllContainers();
		PrintAllMetrics.METER_REGISTRY = this.meterRegistry;
	}

    @AfterAll
    static void afterAll() {
    	PrintAllMetrics.printAllMetrics();
	}

    @Configuration
	@EnableAutoConfiguration
	public static class AbstractITConfiguration {
    	// do nothing
    }

    private static class PrintAllMetrics {
    	// set by AbstractIT @PostConstruct from @Autowired
    	// Used by AbstractIT @AfterAll to print all Metric IDs and Measurements
        private static MeterRegistry METER_REGISTRY;
        private static void printAllMetrics() {
    		assert METER_REGISTRY != null : "METER_REGISTRY must not be null";
    		final List<Meter> meters = METER_REGISTRY.getMeters();
    		if (meters.isEmpty()) {
    			log.info("No meters");
    		} else {
    			meters.forEach(meter -> {log.atInfo().addArgument(() -> meter.getId()).addArgument(() -> meter.measure()).log("Meter: {} = {}");});
    		}
    	}
    }
}
