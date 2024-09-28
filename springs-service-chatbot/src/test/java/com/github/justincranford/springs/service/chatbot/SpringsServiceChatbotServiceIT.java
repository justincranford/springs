package com.github.justincranford.springs.service.chatbot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.ollama.OllamaContainer;

import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@SuppressWarnings({"nls", "static-method", "resource" })
public class SpringsServiceChatbotServiceIT extends AbstractIT {
	/**
	 * True => Automatically start and use an ephemeral ollama container
	 * 
	 * False => Reuse external, manually started, container
	 *  - Example start:  docker run --rm -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama:0.3.12
	 *  = Example shell:  docker exec -it ollama bash
	 */
	private static final boolean USE_TEST_CONTAINER = false;

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

	/**
	 * @see OllamaContainer#getEndpoint
	 */
	@DynamicPropertySource
	public static void ollamaContainerProperties(final DynamicPropertyRegistry registry) {
		final OllamaContainer instance = SpringsUtilTestContainers.OLLAMA.getInstance();
		if (instance.isRunning()) {
			log.info("Setting dynamic properties from SpringsUtilTestContainers.OLLAMA");
			registry.add("springs.service.chatbot.protocol", () -> "http");
			registry.add("springs.service.chatbot.host",     () -> instance.getHost());
			registry.add("springs.service.chatbot.port",     () -> instance.getMappedPort(11434));
		} else {
			log.info("Will use static properties from springs-service-chatbot.properties");
		}
	}

	@Order(1)
	@Test
	void testProperties() {
		final String  protocol = springsServiceChatbotProperties().getProtocol();
		final String  host     = springsServiceChatbotProperties().getHost();
		final Integer port     = springsServiceChatbotProperties().getPort();
		log.info("springs.service.chatbot.protocol: {}", protocol);
		log.info("springs.service.chatbot.host:     {}", host);
		log.info("springs.service.chatbot.port:     {}", port);
		assertThat(host).isNotEmpty();
		assertThat(port).isNotNull();
	}

	@Order(2)
	@Test
	void testEndpoint() {
		assumeThat(USE_TEST_CONTAINER).isTrue();
		log.info("url: {}", SpringsUtilTestContainers.OLLAMA.getInstance().getEndpoint());
	}

	@Order(3)
	@Test
	void testIsAlive() {
        final String isAlive = springsServiceChatbotClient().isAlive();
        log.info("isAlive:\n{}", isAlive);
        assertThat(isAlive).isEqualTo("Ollama is running");
	}

	@Order(4)
	@Test
	void testTags() {
        final String tags = springsServiceChatbotClient().tags();
        log.info("tags:\n{}", tags);
        assertThat(tags).startsWith("{\"models\":[").endsWith("]}");
	}

	@Order(5)
	@Test
	void testPs() {
        final String ps = springsServiceChatbotClient().ps();
        log.info("ps:\n{}", ps);
        assertThat(ps).startsWith("{\"models\":[").endsWith("]}");
	}

	@Order(6)
	@Test
	void testChat() {
        final String chat = springsServiceChatbotClient().chat("""
       		{
        		"model": "llama3.2",
        		"prompt": "Why is the sky blue?"
			}
      		""");
        log.info("chat: {}\n", chat);
	}
}
