package com.github.justincranford.springs.service.http;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.service.http.config.SpringsUtilHttpConfiguration;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
	webEnvironment=WebEnvironment.RANDOM_PORT,
	classes={
		SpringsUtilHttpConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
	}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"static-method"})
public class AbstractIT {
	@PostConstruct
	public void postConstruct() {
		this.httpBaseUrl     = "http://"  + serverAddress() + ":" + localServerPort();
		this.httpsBaseUrl    = "https://" + serverAddress() + ":" + localServerPort();
		this.httpsPskBaseUrl = "https://" + serverAddress() + ":" + 9443;
		log.info("urls, httpBaseUrl: {}, httpsBaseUrl: {}, httpsPskBaseUrl: {}", this.httpBaseUrl, this.httpsBaseUrl, this.httpsPskBaseUrl);
	}

	@Value("${server.address}")
	private String serverAddress;

	@LocalServerPort
	private long localServerPort;

    @Autowired
    private String httpBaseUrl;

    @Autowired
    private String httpsBaseUrl;

    @Autowired
    private String httpsPskBaseUrl;

    @Autowired
	private RestTemplate httpRestTemplate;

    @Configuration
	public static class AbstractITConfiguration {
		@Bean
	    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	        return http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll()).csrf(csrf -> csrf.disable()).build();
	    }
    }
}
