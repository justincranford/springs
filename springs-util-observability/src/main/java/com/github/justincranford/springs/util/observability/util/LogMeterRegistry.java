package com.github.justincranford.springs.util.observability.util;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
//import io.micrometer.prometheusmetrics.PrometheusConfig;
//import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;

@Configuration
@SuppressWarnings({"nls", "static-method"})
@Slf4j
public class LogMeterRegistry {
    @Autowired
	private MeterRegistry meterRegistry;

    private static MeterRegistry METER_REGISTRY;

	@PostConstruct
	private void postConstruct() {
		METER_REGISTRY = this.meterRegistry;
	}

	@PreDestroy
	private void preDestroy() {
		assert METER_REGISTRY != null : "METER_REGISTRY must not be null";
		final List<Meter> meters = METER_REGISTRY.getMeters();
		if (meters.isEmpty()) {
			log.atInfo().log("No meters");
		} else {
			meters.forEach(meter -> {log.atInfo().addArgument(() -> meter.getId()).addArgument(() -> meter.measure()).log("Meter: {} = {}");});
		}
	}
}
