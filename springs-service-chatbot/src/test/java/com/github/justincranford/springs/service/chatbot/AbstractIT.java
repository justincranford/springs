package com.github.justincranford.springs.service.chatbot;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.actuate.observability.AutoConfigureObservability;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.service.chatbot.config.SpringsServiceChatbotClient;
import com.github.justincranford.springs.service.chatbot.config.SpringsServiceChatbotConfiguration;
import com.github.justincranford.springs.service.chatbot.properties.SpringsServiceChatbotProperties;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
	webEnvironment = SpringBootTest.WebEnvironment.NONE,
	classes = {
		SpringsServiceChatbotConfiguration.class
	}
)
@EnableAutoConfiguration
@AutoConfigureObservability
@Import(SpringsServiceChatbotConfiguration.class)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
public abstract class AbstractIT {
//	@LocalServerPort
//	private long localServerPort;
	@Autowired
	private MeterRegistry meterRegistry;
	@Autowired
	private ApplicationContext applicationContext;
	@Autowired
	private SpringsServiceChatbotProperties springsServiceChatbotProperties;
	@Autowired
	private SpringsServiceChatbotClient springsServiceChatbotClient;
}
