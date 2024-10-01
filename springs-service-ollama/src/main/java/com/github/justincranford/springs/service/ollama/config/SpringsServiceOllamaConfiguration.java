package com.github.justincranford.springs.service.ollama.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.ollama.config.client.SpringsServiceOllamaServiceConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;

@Configuration
@EnableConfigurationProperties
@Import({
	SpringsUtilJsonConfiguration.class,
	SpringsServiceOllamaServiceConfiguration.class
})
public class SpringsServiceOllamaConfiguration {
	// do nothing
}
