package com.github.justincranford.springs.authenticationorm.users.authentication.service.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.authenticationorm.users.authentication.service.PersonaService;

@Configuration
@ComponentScan(
	basePackageClasses={PersonaService.class}
)
public class SpringsAuthenticationOrmUsersAuthenticationUserDetailsConfiguration {
	// do nothing
}
