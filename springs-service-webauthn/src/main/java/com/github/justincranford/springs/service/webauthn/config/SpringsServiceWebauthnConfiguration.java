package com.github.justincranford.springs.service.webauthn.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.actions.config.ActionsConfiguration;
import com.github.justincranford.springs.service.webauthn.authenticate.config.AuthenticationConfiguration;
import com.github.justincranford.springs.service.webauthn.credential.config.CredentialConfiguration;
import com.github.justincranford.springs.service.webauthn.register.config.RegistrationConfiguration;
import com.github.justincranford.springs.service.webauthn.relyingparty.config.RelyingPartyConfiguration;
import com.github.justincranford.springs.util.certs.config.SpringsUtilHttpsConfiguration;

@Configuration
@EnableConfigurationProperties
@Import(value = {
	SpringsUtilHttpsConfiguration.class,
	RelyingPartyConfiguration.class,
	ActionsConfiguration.class,
	CredentialConfiguration.class,
	RegistrationConfiguration.class,
	AuthenticationConfiguration.class
})
public class SpringsServiceWebauthnConfiguration {
	// do nothing
}
