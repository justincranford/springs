package com.github.justincranford.springs.util.security.hashes.config;

import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;
import com.github.justincranford.springs.util.security.hashes.encoder.config.EncodersConfiguration;
import com.github.justincranford.springs.util.security.hashes.properties.SpringsUtilSecurityHashesProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@EnableConfigurationProperties
@ComponentScan(
    basePackageClasses = { SpringsUtilSecurityHashesProperties.class }
)
@Import({
    SpringsUtilObservabilityConfiguration.class,
    SpringsUtilJsonConfiguration.class,
    EncodersConfiguration.class
})
public class SpringsUtilSecurityHashesConfiguration {
    // do nothing
}
