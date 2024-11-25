package com.github.justincranford.springs.server.authentication.user.config;

import com.github.justincranford.springs.server.authentication.user.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.user.provider.PersonaEmailPasswordAuthenticationProvider;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={PersonaEmailPasswordAuthenticationProvider.class, PersonUsernamePasswordAuthenticationProvider.class}
)
public class SpringsServerAuthenticationUsersConfiguration {
	// do nothing
}
