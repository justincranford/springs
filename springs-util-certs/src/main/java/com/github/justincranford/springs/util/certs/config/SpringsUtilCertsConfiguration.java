package com.github.justincranford.springs.util.certs.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.certs.tls.config.SpringsUtilCertsTlsConfiguration;

@Configuration
@EnableConfigurationProperties
@Import(value = {
	SpringsUtilCertsTlsConfiguration.class
})
public class SpringsUtilCertsConfiguration {
	// do nothing
}
