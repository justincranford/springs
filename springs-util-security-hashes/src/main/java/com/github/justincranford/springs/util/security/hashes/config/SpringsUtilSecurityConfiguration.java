package com.github.justincranford.springs.util.security.hashes.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodersConfiguration;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityProperties;

@Configuration
@EnableConfigurationProperties
@ComponentScan(
	basePackageClasses = {SpringsUtilSecurityProperties.class, EncodersConfiguration.class}
)
@Import({
	SpringsUtilObservabilityConfiguration.class,
	SpringsUtilJsonConfiguration.class
})
public class SpringsUtilSecurityConfiguration {
	// do nothing
}
