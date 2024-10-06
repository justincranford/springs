package com.github.justincranford.springs.service.webauthn;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.certs.config.SpringsUtilCertsConfiguration;

@Configuration
@EnableConfigurationProperties
@Import(value = {
	SpringsUtilCertsConfiguration.class
})
public class SpringsServiceWebauthnConfiguration {
	// do nothing
}
