package com.github.justincranford.springs.util.https.server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.https.server.TlsInitializer;

import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableAutoConfiguration
@EnableConfigurationProperties
@Import(value={
	TlsInitializer.class,
	SpringsUtilHttpsServerPskConfiguration.class
})
@Slf4j
@SuppressWarnings({"static-method"})
public class SpringsUtilHttpsServerConfiguration {
	@Bean
	public String httpsBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpsBaseUrl = "https://" + serverAddress + ":" + serverPort;
		log.info("httpsBaseUrl: {}", httpsBaseUrl);
		return httpsBaseUrl;
	}

	@Bean
	public String httpsPskBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpsPskBaseUrl = "https://" + serverAddress + ":" + (serverPort + 1000);
		log.info("httpsPskBaseUrl: {}", httpsPskBaseUrl);
		return httpsPskBaseUrl;
	}
}
