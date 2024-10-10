package com.github.justincranford.springs.service.webauthn.authenticate.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.authenticate.controller.AuthenticationController;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.AuthenticationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.authenticate.service.AuthenticationService;

@Configuration
@Import({AuthenticationController.class, AuthenticationService.class})
@SuppressWarnings({"static-method"})
public class AuthenticationConfiguration {
	@Bean
	public AuthenticationRepositoryOrm authenticationRepositoryOrm() {
		return new AuthenticationRepositoryOrm();
	}
}
