package com.github.justincranford.springs.util.observability.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.observability.handler.TraceObservationHandler;
import com.github.justincranford.springs.util.observability.util.LogMeterRegistry;

@Configuration
@Import({SpringsUtilMeterRegistryConfiguration.class, SpringsUtilTraceRegistryConfiguration.class, TraceObservationHandler.class, LogMeterRegistry.class})
public class SpringsUtilObservabilityConfiguration {
	// do nothing
}
