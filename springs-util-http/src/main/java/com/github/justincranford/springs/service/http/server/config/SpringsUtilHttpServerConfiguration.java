package com.github.justincranford.springs.service.http.server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.http.server.HelloWorldController;
import com.github.justincranford.springs.util.http.logging.config.SpringsUtilHttpRequestLogConfiguration;
import com.github.justincranford.springs.util.http.ratelimit.config.SpringsUtilHttpRateLimitConfiguration;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableAutoConfiguration
@EnableConfigurationProperties
@Import(value={
	HelloWorldController.class,
	SpringsUtilHttpRequestLogConfiguration.class,
	SpringsUtilHttpRateLimitConfiguration.class
})
@Slf4j
@SuppressWarnings({"static-method"})
public class SpringsUtilHttpServerConfiguration {
	@Bean
	public String httpBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpBaseUrl = "http://" + serverAddress + ":" + serverPort;
		log.info("httpBaseUrl: {}", httpBaseUrl);
		return httpBaseUrl;
	}
}
