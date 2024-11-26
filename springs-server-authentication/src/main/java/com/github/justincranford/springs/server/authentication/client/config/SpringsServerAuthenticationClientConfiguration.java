package com.github.justincranford.springs.server.authentication.client.config;

import com.github.justincranford.springs.server.authentication.client.controller.AuthenticationStatusController;
import com.github.justincranford.springs.server.authentication.client.provider.ClientNameSecretAuthenticationProvider;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={ClientNameSecretAuthenticationProvider.class, AuthenticationStatusController.class}
)
public class SpringsServerAuthenticationClientConfiguration {
	// do nothing
}
