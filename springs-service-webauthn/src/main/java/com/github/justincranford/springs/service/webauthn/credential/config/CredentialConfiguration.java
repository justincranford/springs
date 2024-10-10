package com.github.justincranford.springs.service.webauthn.credential.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;
import com.yubico.webauthn.CredentialRepository;

@Configuration
@Import({RegistrationService.class})
@SuppressWarnings({"static-method"})
public class CredentialConfiguration {
	@Bean
	public CredentialRepository credentialRepository() {
		return new CredentialRepositoryOrm();
	}
}
