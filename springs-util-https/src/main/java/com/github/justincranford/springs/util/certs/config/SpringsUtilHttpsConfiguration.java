package com.github.justincranford.springs.util.certs.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.certs.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.certs.client.config.SpringsUtilTlsClientsConfiguration;
import com.github.justincranford.springs.util.certs.server.config.SpringsUtilHttpsServerConfiguration;
import com.github.justincranford.springs.util.http.config.SpringsUtilHttpConfiguration;

@Configuration
@Import(value = {
	SpringsUtilHttpConfiguration.class,
	SpringsUtilTlsClientsConfiguration.class,
	SpringsUtilHttpsClientsConfiguration.class,
	SpringsUtilHttpsServerConfiguration.class
})
public class SpringsUtilHttpsConfiguration {
	// do nothing
}
