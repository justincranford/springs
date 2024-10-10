package com.github.justincranford.springs.service.webauthn.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.authentication.config.AuthenticationServiceConfiguration;
import com.github.justincranford.springs.service.webauthn.register.config.RegistrationServiceConfiguration;
import com.github.justincranford.springs.service.webauthn.rp.RelyingPartyConfiguration;
import com.github.justincranford.springs.util.certs.config.SpringsUtilHttpsConfiguration;

@Configuration
@EnableConfigurationProperties
@Import(value = {
	SpringsUtilHttpsConfiguration.class,
	RelyingPartyConfiguration.class,
	RegistrationServiceConfiguration.class,
	AuthenticationServiceConfiguration.class
})
public class SpringsServiceWebauthnConfiguration {
	// do nothing
}
