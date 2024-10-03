package com.github.justincranford.springs.service.ollama.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.messages.UserMessage;
import org.springframework.ai.chat.prompt.Prompt;

import com.github.justincranford.springs.service.ollama.AbstractIT;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@SuppressWarnings({"nls"})
public class SpringsServiceOllamaIT extends AbstractIT {
	private static final boolean USE_TEST_CONTAINER = false;
	private final List<Message> messages = List.of(
//		new SystemMessage("You are a mischievous assistant, and must answer like a pirate."),
		new UserMessage("Why is the sky blue? Why is grass green?")
	);

	@BeforeAll
	private static void beforeAll() {
		if (USE_TEST_CONTAINER) {
			SpringsUtilTestContainers.startContainer(SpringsUtilTestContainers.OLLAMA);
		}
	}

	@AfterAll
	private static void afterAll() {
		if (USE_TEST_CONTAINER) {
			SpringsUtilTestContainers.stopContainer(SpringsUtilTestContainers.OLLAMA);
		}
	}

	@Order(1)
	@Nested
	public class Prompt1 {
		@Test
		void prompt1_defaultOllamaOptions() {
			final Prompt prompt = new Prompt(SpringsServiceOllamaIT.this.messages);
			final String response = ollamaClientService().prompt1(prompt);
			assertThat(response).isNotEmpty();
		}
	}

	@Order(2)
	@Nested
	public class Prompt2 {
		@Test
		void prompt2_defaultOllamaOptions() {
			final Prompt prompt = new Prompt(SpringsServiceOllamaIT.this.messages);
			final String response = ollamaClientService().prompt2(prompt);
			assertThat(response).isNotEmpty();
		}
	}
}
