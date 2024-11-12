package com.github.justincranford.springs.authenticationorm.users.logging.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={RequestLoggingFilter.class}
)
public class SpringsAuthenticationOrmUsersRequestLoggingConfiguration {
	// do nothing
}
