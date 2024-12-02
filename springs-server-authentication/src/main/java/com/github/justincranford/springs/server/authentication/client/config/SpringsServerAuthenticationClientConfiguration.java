package com.github.justincranford.springs.server.authentication.client.config;

import com.github.justincranford.springs.server.authentication.client.controller.AuthenticationStatusController;
import com.github.justincranford.springs.server.authentication.client.filter.ClientJwtBearerTokenAuthenticationFilter;
import com.github.justincranford.springs.server.authentication.client.provider.ClientJwtAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.client.provider.ClientNameSecretAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.client.service.JwtIssuerService;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={
		AuthenticationStatusController.class,
		JwtIssuerService.class,
		ClientNameSecretAuthenticationProvider.class,
		ClientJwtBearerTokenAuthenticationFilter.class,
		ClientJwtAuthenticationProvider.class
	}
)
public class SpringsServerAuthenticationClientConfiguration {
	// do nothing
}
