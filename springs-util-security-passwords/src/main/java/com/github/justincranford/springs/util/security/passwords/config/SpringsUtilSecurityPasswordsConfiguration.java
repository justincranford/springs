package com.github.justincranford.springs.util.security.passwords.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;
import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

@Configuration
@EnableConfigurationProperties
@ComponentScan(
	basePackageClasses = {SpringsUtilSecurityPasswordsProperties.class}
)
@Import(
	value = {SpringsUtilSecurityHashesConfiguration.class}
)
public class SpringsUtilSecurityPasswordsConfiguration {
	// do nothing
}
