package com.github.justincranford.springs.service.chatbot.client;

import static org.assertj.core.api.Assertions.fail;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.ClassOrderer;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestClassOrder;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.ollama.OllamaContainer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.service.chatbot.AbstractIT;
import com.github.justincranford.springs.service.chatbot.model.Abstract;
import com.github.justincranford.springs.service.chatbot.model.Chat;
import com.github.justincranford.springs.service.chatbot.model.Generate;
import com.github.justincranford.springs.service.chatbot.model.Ps;
import com.github.justincranford.springs.service.chatbot.model.Pull;
import com.github.justincranford.springs.service.chatbot.model.Tags;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

/**
 * TODO:
 * create
 * show
 * copy
 * delete
 * push
 * embeddings
 */
@TestClassOrder(ClassOrderer.OrderAnnotation.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@Slf4j
@SuppressWarnings({"nls", "resource" })
public class SpringsServiceChatbotServiceIT extends AbstractIT {
	/**
	 * True => Automatically start and use an ephemeral ollama container
	 * 
	 * False => Reuse external, manually started, container
	 *  - Example start:  docker run --rm -d -v .:/here -v ollama:/root/.ollama -p 11434:11434 --name ollama ollama/ollama:0.3.12
	 *  = Example shell:  docker exec -it ollama bash
	 */
	private static final boolean USE_TEST_CONTAINER = false;
	private static final long TIMEOUT_MILLIS = 30000L;
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
	public class PropertiesIT {
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
	}

	@Order(2)
	@Nested
	@TestClassOrder(ClassOrderer.OrderAnnotation.class)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	public class TestContainersIT {
		@Order(1)
		@Test
		void testEndpoint() {
			assumeThat(USE_TEST_CONTAINER).isTrue();
			log.info("url: {}", SpringsUtilTestContainers.OLLAMA.getInstance().getEndpoint());
		}
	}

	@Order(3)
	@Nested
	@TestClassOrder(ClassOrderer.OrderAnnotation.class)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	public class AvailabilityIT {
		@Order(1)
		@Test
		void testIsAlive() {
	        final boolean response = springsServiceChatbotClient().alive();
			assertThat(response).isTrue();
		}
	}

	@Order(4)
	@Nested
	@TestClassOrder(ClassOrderer.OrderAnnotation.class)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	public class ResponsivenessIT {
		@Order(1)
		@Test
		void testTags() {
	        final Tags.Response response = springsServiceChatbotClient().tags();
			assertThat(response).isNotNull();
		}

		@Order(2)
		@Test
		void testPs() {
	        final Ps.Response response = springsServiceChatbotClient().ps();
			assertThat(response.models()).isNotNull();
		}
	}

	@Order(5)
	@Nested
	@TestClassOrder(ClassOrderer.OrderAnnotation.class)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	public class ModelsIT {
		@Order(1)
		@Test
		void testPull() {
	        final Pull.Request  request  = Pull.Request.builder().model(MODEL).stream(Boolean.FALSE).build();
			final Pull.Response response = springsServiceChatbotClient().pull(request);
			assertThat(response).isNotNull();
		}

		@Order(2)
		@Test
		void testPs() {
	        final Ps.Response response = springsServiceChatbotClient().ps();
			assertThat(response.models()).isNotNull();
		}
	}

	@Order(6)
	@Nested
	@TestClassOrder(ClassOrderer.OrderAnnotation.class)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	public class GenerateIT {
		@Order(1)
		@Test
		void testLoad() {
	        final Generate.Request  request  = Generate.Request.builder().model(MODEL).stream(Boolean.FALSE).keepAlive(Long.valueOf(-1L)).build();
	        final Generate.Response response = springsServiceChatbotClient().generate(request);
			assertThat(response.response()).isNotNull();
		}

		@Order(2)
		@Test
		void testUnload() {
	        final Generate.Request  request  = Generate.Request.builder().model(MODEL).stream(Boolean.FALSE).keepAlive(Long.valueOf(0L)).build();
	        final Generate.Response response = springsServiceChatbotClient().generate(request);
			assertThat(response.response()).isNotNull();
		}

		@Order(3)
		@Test
		void testGenerateStream() {
	        final Generate.Request request = Generate.Request.builder().model(MODEL).stream(Boolean.TRUE)
        		.prompt("Why is the sky blue?")
        		.options(
    				Abstract.Options.builder()
    					.temperature(Double.valueOf(SecureRandomUtil.SECURE_RANDOM.nextDouble(5d, 10d)))
    					.seed(Integer.valueOf(SecureRandomUtil.SECURE_RANDOM.nextInt()))
    					.build())
        		.build();

    		final long totalNanos = System.nanoTime();
//    		final long requestNanos = System.nanoTime();
	        final BlockingQueue<Generate.Response> responses = springsServiceChatbotClient().generateStream(request);
//	        try {
//				log.info("generate request [{} usec, {} usec]:\n{}", micros(requestNanos), micros(totalNanos), objectMapper().writeValueAsString(request));
//			} catch (JsonProcessingException e) {
//		        log.info("generate request, exception:", e);
//		        throw new RuntimeException(e);
//			}
	        while (true) {
        		final long responseNanos = System.nanoTime();
	        	try {
					final Generate.Response response = responses.poll(TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
			        log.info("generate response [{} usec, {} msec]:\n{}", micros(responseNanos), millis(totalNanos), objectMapper().writeValueAsString(response));
					if (response == null) {
				        log.info("generate response timed out [{} usec, {} msec]", micros(responseNanos), millis(totalNanos));
				        fail("Timed out");
						break;
					} else if (response.done().booleanValue()) {
				        log.info("done [{} usec, {} msec]: true, done_reason: {}", micros(responseNanos), millis(totalNanos), response.doneReason());
						break;
					}
				} catch (InterruptedException e) {
			        log.warn("generate response, interrupted exception [{} usec, {} msec]", micros(responseNanos), millis(totalNanos), e);
    			    Thread.currentThread().interrupt();
				} catch (JsonProcessingException e) {
			        log.error("generate response, processing exception [{} usec, {} msec]", micros(responseNanos), millis(totalNanos), e);
				}
	        }
		}

		private Float micros(final long startNanos) {
			return Float.valueOf((System.nanoTime() - startNanos) / 1000F);
		}

		private Float millis(final long startNanos) {
			return Float.valueOf((System.nanoTime() - startNanos) / 1000000F);
		}
	}

	@Order(7)
	@Nested
	@TestClassOrder(ClassOrderer.OrderAnnotation.class)
	@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
	public class ChatIT {
		@Order(1)
		@Test
		void testLoad() {
			final Chat.Request  request  = Chat.Request.builder().model(MODEL).stream(Boolean.FALSE).keepAlive(Long.valueOf(-1L)).build();
	        final Chat.Response response = springsServiceChatbotClient().chat(request);
			assertThat(response.message()).isNotNull();
		}

		@Order(2)
		@Test
		void testUnload() {
	        final Chat.Request  request  = Chat.Request.builder().model(MODEL).stream(Boolean.FALSE).keepAlive(Long.valueOf(0L)).build();
	        final Chat.Response response = springsServiceChatbotClient().chat(request);
			assertThat(response.message()).isNotNull();
		}

		@Order(3)
		@Test
		void testChat() {
	        final Chat.Request request = Chat.Request.builder().model(MODEL).stream(Boolean.FALSE)
        		.messages(List.of(
    				Chat.Request.Message.builder().role(Chat.Request.Message.Role.USER).content("Why is the sky blue?").build()
				))
        		.options(
    				Abstract.Options.builder()
    					.temperature(Double.valueOf(SecureRandomUtil.SECURE_RANDOM.nextDouble(5d, 10d)))
    					.seed(Integer.valueOf(SecureRandomUtil.SECURE_RANDOM.nextInt()))
    					.build())
        		.build();
	        final Chat.Response response = springsServiceChatbotClient().chat(request);
			assertThat(response.message()).isNotNull();
		}
	}
}
