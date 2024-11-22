package com.github.justincranford.springs.service.ollama;

import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.service.ollama.client.SpringsServiceOllama;
import com.github.justincranford.springs.service.ollama.config.SpringsServiceOllamaConfiguration;

import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@SpringBootTest(
	webEnvironment = SpringBootTest.WebEnvironment.NONE,
	classes = {
		SpringsServiceOllamaConfiguration.class
	}
)
@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
@EnableAutoConfiguration
@AutoConfigureObservability
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Observed
public abstract class AbstractIT {
	/**
	 * @see SpringsServiceOllama
	 */
	@Autowired
	private SpringsServiceOllama ollamaClientService;

	@DynamicPropertySource
	static void properties(final DynamicPropertyRegistry registry) {
		registry.add("bootstrap.testcontainers.enabled",            () -> "false");
		registry.add("bootstrap.testcontainers.containers.ollama1", () -> "ollama/ollama:0.4.3");
	}
}
