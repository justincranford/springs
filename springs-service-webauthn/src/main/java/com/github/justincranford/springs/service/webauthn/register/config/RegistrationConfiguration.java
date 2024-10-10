package com.github.justincranford.springs.service.webauthn.register.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

@Configuration
@Import({RegistrationService.class})
@SuppressWarnings({"static-method"})
public class RegistrationConfiguration {
	@Bean
	public RegistrationRepositoryOrm registrationRepositoryOrm() {
		return new RegistrationRepositoryOrm();
	}
}
