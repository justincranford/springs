package com.github.justincranford.springs.authenticationorm.users.authentication;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={PersonaEmailPasswordAuthenticationProvider.class, PersonUsernamePasswordAuthenticationProvider.class}
)
public class SpringsAuthenticationOrmUsersAuthenticationConfiguration {
	// do nothing
}
