package com.github.justincranford.springs.service.chatbot;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
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
	webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
	classes = {
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
@SuppressWarnings("nls")
public class AbstractIT {
	@LocalServerPort
	private long localServerPort;
	@Autowired
	private MeterRegistry meterRegistry;
	@Autowired
	private ApplicationContext applicationContext;
	@Autowired
	private SpringsServiceChatbotProperties springsServiceChatbotProperties;

	@BeforeAll
	private static void beforeAll() {
		SpringsUtilTestContainers.startContainers(List.of(SpringsUtilTestContainers.OLLAMA));
	}

	/**
	 * @see OllamaContainer#getEndpoint
	 */
	@SuppressWarnings("resource")
	@DynamicPropertySource
	public static void ollamaContainerProperties(final DynamicPropertyRegistry registry) {
		final OllamaContainer instance = SpringsUtilTestContainers.OLLAMA.getInstance();
		if (instance.isRunning()) {
			log.info("Setting dynamic properties from SpringsUtilTestContainers.OLLAMA");
			registry.add("springs.service.chatbot.host", () -> instance.getHost());
			registry.add("springs.service.chatbot.port", () -> instance.getMappedPort(11434));
		} else {
			log.info("Using static properties");
		}
	}
}
