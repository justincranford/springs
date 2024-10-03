package com.github.justincranford.springs.service.ollama;

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

@SpringBootTest(
	webEnvironment = SpringBootTest.WebEnvironment.NONE,
	classes = {
		SpringsServiceOllamaConfiguration.class
	}
)
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
}
