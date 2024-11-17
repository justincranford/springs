package com.github.justincranford.springs.util.observability.trace;

import io.micrometer.observation.ObservationRegistry;
import io.micrometer.observation.aop.ObservedAspect;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@SuppressWarnings({"unused", "static-method" })
public class SpringsUtilTraceRegistryConfiguration {
    @Bean
    ObservedAspect observedAspect(final ObservationRegistry observationRegistry) {
        return new ObservedAspect(observationRegistry);
    }
}
