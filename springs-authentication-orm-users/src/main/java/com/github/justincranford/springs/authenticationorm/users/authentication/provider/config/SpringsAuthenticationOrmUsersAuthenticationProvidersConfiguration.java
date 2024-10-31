package com.github.justincranford.springs.authenticationorm.users.authentication.provider.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonaEmailPasswordAuthenticationProvider;

@Configuration
@ComponentScan(
	basePackageClasses={PersonaEmailPasswordAuthenticationProvider.class, PersonUsernamePasswordAuthenticationProvider.class}
)
public class SpringsAuthenticationOrmUsersAuthenticationProvidersConfiguration {
	// do nothing
}
