package com.github.justincranford.springs.util.security.passwords.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.util.security.passwords.properties.SpringsUtilSecurityPasswordsProperties;

@Configuration
@EnableConfigurationProperties
@ComponentScan(
	basePackageClasses = {SpringsUtilSecurityPasswordsProperties.class}
)
public class SpringsUtilSecurityPasswordsConfiguration {
	// do nothing
}
