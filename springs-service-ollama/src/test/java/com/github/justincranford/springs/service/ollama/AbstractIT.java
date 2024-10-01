package com.github.justincranford.springs.service.ollama;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.ollama.client.SpringsServiceOllamaService;
import com.github.justincranford.springs.service.ollama.config.SpringsServiceOllamaConfiguration;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
	webEnvironment = SpringBootTest.WebEnvironment.NONE,
	classes = {
		SpringsServiceOllamaConfiguration.class
	}
)
@EnableAutoConfiguration
@AutoConfigureObservability
@Import(SpringsServiceOllamaConfiguration.class)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
public abstract class AbstractIT {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private MeterRegistry meterRegistry;
	@Autowired
	private ApplicationContext applicationContext;
	@Autowired
	private SpringsServiceOllamaService springsServiceOllamaService;
}
