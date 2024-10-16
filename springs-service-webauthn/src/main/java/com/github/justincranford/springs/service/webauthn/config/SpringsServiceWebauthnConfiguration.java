package com.github.justincranford.springs.service.webauthn.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.service.http.server.HelloWorldController;
import com.github.justincranford.springs.service.webauthn.actions.config.ActionsConfiguration;
import com.github.justincranford.springs.service.webauthn.authenticate.config.AuthenticationConfiguration;
import com.github.justincranford.springs.service.webauthn.credential.config.CredentialConfiguration;
import com.github.justincranford.springs.service.webauthn.register.config.RegistrationConfiguration;
import com.github.justincranford.springs.service.webauthn.relyingparty.config.RelyingPartyConfiguration;
import com.github.justincranford.springs.util.certs.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableAutoConfiguration(
		exclude = {
			UserDetailsServiceAutoConfiguration.class
		}
	)
@EnableConfigurationProperties
@Import(value = {
    SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilHttpsConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	RelyingPartyConfiguration.class,
	ActionsConfiguration.class,
	CredentialConfiguration.class,
	RegistrationConfiguration.class,
	AuthenticationConfiguration.class,
	HelloWorldController.class
})
@Slf4j
@SuppressWarnings({"nls", "static-method"})
public class SpringsServiceWebauthnConfiguration {
	@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
        	.authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
        	.csrf(csrf -> csrf.disable());
        return http.build();
    }

	@Bean
	public String httpBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpBaseUrl = "http://"  + serverAddress + ":" + serverPort;
		log.info("httpBaseUrl: {}", httpBaseUrl);
		return httpBaseUrl;
	}

	@Bean
	public String httpsBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpsBaseUrl = "https://"  + serverAddress + ":" + serverPort;
		log.info("httpsBaseUrl: {}", httpsBaseUrl);
		return httpsBaseUrl;
	}
}
