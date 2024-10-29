package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={PersonaUserDetailsService.class}
)
public class SpringsAuthenticationOrmUsersAuthenticationPropertiesConfiguration {
	// do nothing
}
