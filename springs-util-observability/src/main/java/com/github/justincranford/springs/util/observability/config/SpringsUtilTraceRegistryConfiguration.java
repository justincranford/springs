package com.github.justincranford.springs.util.observability.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;

@Configuration
@SuppressWarnings({"nls", "static-method"})
public class SpringsUtilTraceRegistryConfiguration {
	@Bean
	ObservedAspect observedAspect(final ObservationRegistry observationRegistry) {
		return new ObservedAspect(observationRegistry);
	}
}
