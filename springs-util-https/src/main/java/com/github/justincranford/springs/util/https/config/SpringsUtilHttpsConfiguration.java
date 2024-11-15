package com.github.justincranford.springs.util.https.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.http.config.SpringsUtilHttpConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilTlsClientsConfiguration;
import com.github.justincranford.springs.util.https.server.config.SpringsUtilHttpsServerConfiguration;

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
