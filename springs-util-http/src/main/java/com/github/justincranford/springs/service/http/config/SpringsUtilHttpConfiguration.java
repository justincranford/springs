package com.github.justincranford.springs.service.http.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.service.http.server.config.SpringsUtilHttpServerConfiguration;

@Configuration
@EnableConfigurationProperties
@Import(value = {
	SpringsUtilHttpClientConfiguration.class,
	SpringsUtilHttpServerConfiguration.class
})
public class SpringsUtilHttpConfiguration {
	// do nothing
}
