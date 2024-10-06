package com.github.justincranford.springs.util.certs.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.certs.server.TomcatTlsInitializer;

@Configuration
@Import({TomcatTlsInitializer.class})
public class SpringsUtilHttpsServerConfiguration {
	// do nothing
}
