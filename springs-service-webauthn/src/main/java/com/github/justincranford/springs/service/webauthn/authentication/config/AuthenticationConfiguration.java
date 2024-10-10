package com.github.justincranford.springs.service.webauthn.authentication.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.authentication.service.AuthenticationService;
import com.github.justincranford.springs.service.webauthn.authentication.repository.AuthenticationRepositoryOrm;

@Configuration
@Import({AuthenticationService.class})
@SuppressWarnings({"static-method"})
public class AuthenticationConfiguration {
	@Bean
	public AuthenticationRepositoryOrm authenticationRepositoryOrm() {
		return new AuthenticationRepositoryOrm();
	}
}
