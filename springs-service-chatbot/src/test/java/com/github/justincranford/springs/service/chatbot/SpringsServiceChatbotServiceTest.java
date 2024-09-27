package com.github.justincranford.springs.service.chatbot;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "static-method", "resource" })
public class SpringsServiceChatbotServiceTest extends AbstractIT {

	@Test
	void testEndpoint() {
		log.info("ollamaUrl: {}", SpringsUtilTestContainers.OLLAMA.getInstance().getEndpoint());
	}

	@Test
	void testProperties() {
		final String  host = springsServiceChatbotProperties().getHost();
		final Integer port = springsServiceChatbotProperties().getPort();
		log.info("springs.service.chatbot.host: {}", host);
		log.info("springs.service.chatbot.port: {}", port);
		assertThat(host).isNotEmpty();
		assertThat(port).isNotNull();
	}

	@Test
	void testConnect() {
		final String ollamaUrl = "http://" + springsServiceChatbotProperties().getHost() + ":" + springsServiceChatbotProperties().getPort();
        log.info("ollamaUrl: {}", ollamaUrl);

        final RestTemplate restTemplate = new RestTemplate();
        final String response = restTemplate.getForObject(ollamaUrl + "/chat", String.class);

        log.info("Ollama Response: {}", response);
	}
}
