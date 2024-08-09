package com.github.justincranford.springs.util.observability.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.observability.handler.TraceObservationHandler;
import com.github.justincranford.springs.util.observability.meter.SpringsUtilMeterRegistryConfiguration;
import com.github.justincranford.springs.util.observability.meter.util.LogMeterRegistry;
import com.github.justincranford.springs.util.observability.trace.SpringsUtilTraceRegistryConfiguration;

@Configuration
@Import({
	SpringsUtilMeterRegistryConfiguration.class,
	SpringsUtilTraceRegistryConfiguration.class,
	LogMeterRegistry.class,
	TraceObservationHandler.class
})
public class SpringsUtilObservabilityConfiguration {
	// do nothing
}
