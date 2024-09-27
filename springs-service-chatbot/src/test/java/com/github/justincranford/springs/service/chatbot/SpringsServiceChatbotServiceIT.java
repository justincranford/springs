package com.github.justincranford.springs.service.chatbot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.testcontainers.ollama.OllamaContainer;

import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@SuppressWarnings({"nls", "static-method", "resource" })
public class SpringsServiceChatbotServiceIT extends AbstractIT {
	/**
	 * Set to false if you want to reuse externally started container, like so:
	 *  > docker run --rm -d -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama:0.3.12
	 */
	private static final boolean USE_TEST_CONTAINER = false;

	@BeforeAll
	private static void beforeAll() {
		if (USE_TEST_CONTAINER) {
			SpringsUtilTestContainers.startContainer(SpringsUtilTestContainers.OLLAMA);
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
			registry.add("springs.service.chatbot.host", () -> instance.getHost());
			registry.add("springs.service.chatbot.port", () -> instance.getMappedPort(11434));
		} else {
			log.info("Will use static properties from springs-service-chatbot.properties");
		}
	}

	@Order(1)
	@Test
	void testProperties() {
		final String  host = springsServiceChatbotProperties().getHost();
		final Integer port = springsServiceChatbotProperties().getPort();
		log.info("springs.service.chatbot.host: {}", host);
		log.info("springs.service.chatbot.port: {}", port);
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
	void testConnect() {
		final String url = "http://" + springsServiceChatbotProperties().getHost() + ":" + springsServiceChatbotProperties().getPort() + "/";
        log.info("url: {}", url);

        final String getResponse = jsonGet(url, String.class);
        log.info("getResponse: {}\n", getResponse);
        assertThat(getResponse).isEqualTo("Ollama is running");

        final String postRequest = """
       		{
        		"model": "mistral-7b",
        		"prompt": "Why is the sky blue?"
			}
      		""";
        final String postResponse = jsonPost(postRequest, url + "/models/load", String.class);
        log.info("postResponse: {}\n", postResponse);
	}

	public <T> T jsonGet(final String url, final Class<T> clazz) {
		final HttpHeaders getHeaders = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"Accept", List.of("application/json")
    	)));
		return http(url, HttpMethod.GET, new HttpEntity<>(getHeaders), clazz);
	}

	public <T> T jsonPost(final String postRequest, final String url, final Class<T> clazz) {
		final HttpHeaders postHeaders = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"Content-Type",		List.of("application/json"),
			"Accept",			List.of("application/json")
    	)));
		return http(url, HttpMethod.POST, new HttpEntity<>(postRequest, postHeaders), clazz);
	}

	private <T> T http(final String url, final HttpMethod post, final HttpEntity<String> entity, final Class<T> clazz) {
		try {
			final ResponseEntity<T> response = super.restTemplate().exchange(url, post, entity, clazz);
            return response.getBody();
        } catch (HttpStatusCodeException e) {
        	log.error("HTTP Error Response: " + e.getStatusCode() + "\nResponse body: " + e.getResponseBodyAsString());
            throw new RuntimeException("HTTP Error Response: " + e.getStatusCode(), e);
        }
	}
}
