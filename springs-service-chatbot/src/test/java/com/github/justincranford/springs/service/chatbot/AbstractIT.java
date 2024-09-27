package com.github.justincranford.springs.service.chatbot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;
import org.testcontainers.ollama.OllamaContainer;

import com.github.justincranford.springs.service.chatbot.config.SpringsServiceChatbotConfiguration;
import com.github.justincranford.springs.service.chatbot.properties.SpringsServiceChatbotProperties;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
	webEnvironment = SpringBootTest.WebEnvironment.NONE,
	classes = {
		AbstractIT.AbstractITConfiguration.class,
		SpringsServiceChatbotConfiguration.class
	}
)
@EnableAutoConfiguration
@AutoConfigureObservability
//@ImportTestcontainers(SpringsUtilTestContainers.class)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
@SuppressWarnings({"nls", "static-method"})
public abstract class AbstractIT {
	@Autowired
	private RestTemplate restTemplate; 
//	@LocalServerPort
//	private long localServerPort;
	@Autowired
	private MeterRegistry meterRegistry;
	@Autowired
	private ApplicationContext applicationContext;
	@Autowired
	private SpringsServiceChatbotProperties springsServiceChatbotProperties;

	@Configuration
	public static class AbstractITConfiguration {
		@Bean
		public RestTemplate restTemplate() {
			final RestTemplate restTemplate = new RestTemplate();
			restTemplate.setErrorHandler(new DefaultResponseErrorHandler());
			return restTemplate;
		}
	}
}
