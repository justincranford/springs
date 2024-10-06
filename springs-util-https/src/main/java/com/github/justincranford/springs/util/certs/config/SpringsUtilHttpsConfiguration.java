package com.github.justincranford.springs.util.certs.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.http.config.SpringsUtilHttpConfiguration;
import com.github.justincranford.springs.util.certs.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.certs.server.config.SpringsUtilHttpsServerConfiguration;

@Configuration
@EnableConfigurationProperties
@Import(value = {
	SpringsUtilHttpConfiguration.class,
	SpringsUtilHttpsClientsConfiguration.class,
	SpringsUtilHttpsServerConfiguration.class
})
public class SpringsUtilHttpsConfiguration {
	// do nothing
}
