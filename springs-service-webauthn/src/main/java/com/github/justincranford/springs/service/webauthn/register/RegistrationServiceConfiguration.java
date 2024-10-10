package com.github.justincranford.springs.service.webauthn.register;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({RegistrationService.class})
public class RegistrationServiceConfiguration {
	// do nothing
}
