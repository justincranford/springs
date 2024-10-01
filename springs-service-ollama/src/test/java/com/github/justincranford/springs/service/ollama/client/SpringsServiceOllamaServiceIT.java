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
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.ollama.api.OllamaOptions;

import com.github.justincranford.springs.service.ollama.AbstractIT;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@SuppressWarnings({"nls"})
public class SpringsServiceOllamaServiceIT extends AbstractIT {
	/**
	 * True => Automatically start and use an ephemeral ollama container
	 * 
	 * False => Reuse external, manually started, container
	 *  - Example start:  docker run --rm -d -v .:/here -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama:0.3.12
	 *  = Example shell:  docker exec -it ollama bash
	 */
	private static final boolean USE_TEST_CONTAINER = false;
	private static final String MODEL = "llama3.2";
//	private static final String MODEL = "llama3.2:1b";
//	private static final String MODEL = "llama3.2:3b";
//	private static final String MODEL = "llama3.2:latest";
//	private static final String MODEL = "mistral-7b";

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
	@TestClassOrder(ClassOrderer.OrderAnnotation.class)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	public class GenerateIT {
		@Order(1)
		@Test
		void testGenerateStream() {
			final List<Message> messages = List.of(
				new UserMessage("Why is the sky blue?"),
				new UserMessage("Why is grass green?")
			);
			final ChatOptions chatOptions = new OllamaOptions()
				.withModel(MODEL)
				.withTemperature(Float.valueOf(SecureRandomUtil.SECURE_RANDOM.nextFloat(5f, 100f)))
				.withSeed(Integer.valueOf(SecureRandomUtil.SECURE_RANDOM.nextInt(0, 100)));
			final ChatResponse chatResponse = springsServiceOllamaService().prompt(messages, chatOptions);
			assertThat(chatResponse).isNotNull();
		}
	}
}
