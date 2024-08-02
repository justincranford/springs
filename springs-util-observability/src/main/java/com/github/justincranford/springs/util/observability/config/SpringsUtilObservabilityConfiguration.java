package com.github.justincranford.springs.util.observability.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({SpringsUtilMeterRegistryConfiguration.class, SpringsUtilTraceRegistryConfiguration.class})
public class SpringsUtilObservabilityConfiguration {
	// do nothing
}
