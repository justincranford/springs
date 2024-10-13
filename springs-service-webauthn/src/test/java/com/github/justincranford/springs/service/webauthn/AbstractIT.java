package com.github.justincranford.springs.service.webauthn;

import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.service.http.server.HelloWorldController;
import com.github.justincranford.springs.service.webauthn.config.SpringsServiceWebauthnConfiguration;
import com.github.justincranford.springs.util.certs.server.TomcatTlsInitializer;

import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes={
		SpringsServiceWebauthnConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
	}
)
@ContextConfiguration(
	initializers={TomcatTlsInitializer.class}
)
@Import({HelloWorldController.class})
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@SuppressWarnings({"nls", "static-method"})
@Slf4j
public class AbstractIT {
	private static final AtomicBoolean BEFORE_EACH_LOG_ONCE = new AtomicBoolean(true);

	@LocalServerPort
	private long localServerPort;

	@Value("${server.address}")
	private String serverAddress;

	/**
	 * @see SpringsUtilHttpClientConfiguration#httpRestTemplate
	 */
	@Autowired
	@Qualifier("httpRestTemplate")
	private RestTemplate httpRestTemplate;

	/**
	 * @see SpringsUtilHttpsClientsConfiguration#mtlsRestTemplate
	 */
	@Autowired(required=false)
	@Qualifier("mtlsRestTemplate")
	private RestTemplate mtlsRestTemplate;

	/**
	 * @see SpringsUtilHttpsClientsConfiguration#stlsRestTemplate
	 */
	@Autowired(required=false)
	@Qualifier("stlsRestTemplate")
	private RestTemplate stlsRestTemplate;

	@Autowired
	private ObjectMapper objectMapper;

	private String httpBaseUrl;
	private String httpsBaseUrl;

	@BeforeEach
	public void beforeEach() {
		this.httpBaseUrl  = "http://"  + this.serverAddress + ":" + this.localServerPort;
		this.httpsBaseUrl = "https://" + this.serverAddress + ":" + this.localServerPort;
		if (BEFORE_EACH_LOG_ONCE.get()) {
			log.info("httpBaseUrl: {}, httpsBaseUrl: {}", this.httpBaseUrl, this.httpsBaseUrl);
			BEFORE_EACH_LOG_ONCE.set(false);
		}
	}

    @Configuration
	@EnableAutoConfiguration(
		exclude = {
			UserDetailsServiceAutoConfiguration.class
		}
	)
    static class AbstractITConfiguration {
		@Bean
	    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	        http
	        	.authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
	        	.csrf(csrf -> csrf.disable());
	        return http.build();
	    }
    }
}
