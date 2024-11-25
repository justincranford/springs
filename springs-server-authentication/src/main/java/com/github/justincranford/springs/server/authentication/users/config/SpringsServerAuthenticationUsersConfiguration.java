package com.github.justincranford.springs.server.authentication.users.config;

import com.github.justincranford.springs.server.authentication.users.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.users.provider.PersonaEmailPasswordAuthenticationProvider;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={PersonaEmailPasswordAuthenticationProvider.class, PersonUsernamePasswordAuthenticationProvider.class}
)
public class SpringsServerAuthenticationUsersConfiguration {
	// do nothing
}
