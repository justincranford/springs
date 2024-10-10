package com.github.justincranford.springs.service.webauthn.register.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.register.service.RegistrationService;

@Configuration
@Import({RegistrationService.class})
public class RegistrationServiceConfiguration {
	// do nothing
}
