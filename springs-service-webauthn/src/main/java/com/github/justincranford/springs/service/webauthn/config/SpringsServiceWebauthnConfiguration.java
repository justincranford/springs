package com.github.justincranford.springs.service.webauthn.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
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
@EnableJpaRepositories(
	basePackageClasses = {},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@Import(value = {
    SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilHttpsConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	CredentialConfiguration.class,
	RegistrationConfiguration.class,
	AuthenticationConfiguration.class,
	RelyingPartyConfiguration.class
//	HelloWorldController.class
})
@Slf4j
@SuppressWarnings({"nls", "static-method"})
public class SpringsServiceWebauthnConfiguration {
	@Bean
	@Order(1)
	public SecurityFilterChain securityFilterChainStaticResources(HttpSecurity http) throws Exception {
	    http.securityMatcher("/static/**")
	    	.authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
	    		.requestMatchers("/static/**").permitAll()
	            .anyRequest().authenticated()
	        )
	    	.csrf(csrf -> csrf.disable());
	    return http.build();
	}

    @Bean
	@Order(3)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/admin/**")
            .authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
        		.anyRequest()
        		.hasRole("ADMIN")
    		)
            .formLogin(Customizer.withDefaults());
        return http.build();
    }

    @Bean
	@Order(4)
    public SecurityFilterChain userSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/user/**")
            .authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer.anyRequest().authenticated())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
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
