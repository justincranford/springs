package com.github.justincranford.springs.util.testcontainers.containers;

import com.github.justincranford.springs.util.testcontainers.AbstractIT;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers.ContainerDescriptor;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.util.List;

@Slf4j
public class TestContainersIT extends AbstractIT {
	public abstract static class AbstractOneTestIT extends AbstractIT {
		@Autowired
		private ConfigurableEnvironment environment;

		@Test
		void shutdown() {
			final List<ContainerDescriptor> containerDescriptors = BootstrapTestContainers.cleanup(this.environment);
			log.info("containerDescriptors: {}", containerDescriptors);
		}
	}

	@Nested
	class EnabledTrue extends AbstractOneTestIT {
		@DynamicPropertySource
		static void properties(final DynamicPropertyRegistry registry) {
			registry.add("bootstrap.testcontainers.enabled", () -> "true");
		}
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class None extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) { /* empty */ }
		}
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class TwoSame extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) {
				registry.add("bootstrap.testcontainers.containers.redis1",         () -> "redis:7.4.0");
				registry.add("bootstrap.testcontainers.containers.ollama1",        () -> "ollama/ollama:0.4.3");
			}
		}
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class TwoDifferent extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) {
				registry.add("bootstrap.testcontainers.containers.redis1",         () -> "redis:7.4.0");
				registry.add("bootstrap.testcontainers.containers.redis2",         () -> "redis:7.4.0");
			}
		}
		@Disabled(value="Comment out to test all. Too slow to test all of them every time.")
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class All extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) {
				registry.add("bootstrap.testcontainers.containers.elasticsearch1", () -> "docker.elastic.co/elasticsearch/elasticsearch:8.16.0");
				registry.add("bootstrap.testcontainers.containers.keycloak1", () -> "keycloak/keycloak:26.0.5");
				registry.add("bootstrap.testcontainers.containers.selenium1", () -> "grafana/otel-lgtm:0.8.0");
				registry.add("bootstrap.testcontainers.containers.kafka1", () -> "confluentinc/cp-kafka:7.7.1");
				registry.add("bootstrap.testcontainers.containers.zipkin1", () -> "openzipkin/zipkin:3.4.2");
				registry.add("bootstrap.testcontainers.containers.dynamodb1", () -> "amazon/dynamodb-local:2.5.3");
				registry.add("bootstrap.testcontainers.containers.postgres1", () -> "postgres:16.3");
				registry.add("bootstrap.testcontainers.containers.grafana1", () -> "selenium/standalone-chrome:130.0");
				registry.add("bootstrap.testcontainers.containers.mongodb1", () -> "mongo:8.0.3");
				registry.add("bootstrap.testcontainers.containers.vault1", () -> "hashicorp/vault:1.18.2");
				registry.add("bootstrap.testcontainers.containers.consul1", () -> "hashicorp/consul:1.19.2");
				registry.add("bootstrap.testcontainers.containers.redis1", () -> "redis:7.4.0");
				registry.add("bootstrap.testcontainers.containers.ollama1", () -> "ollama/ollama:0.4.3");
			}
		}
	}

	@Nested
	class EnabledPreferred extends AbstractOneTestIT {
		@DynamicPropertySource
		static void properties(final DynamicPropertyRegistry registry) {
			registry.add("bootstrap.testcontainers.enabled", () -> "preferred");
		}
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class None extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) { /* empty */ }
		}
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class Two extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) {
//				registry.add("bootstrap.testcontainers.containers.redis1", () -> "redis:7.4.0");
//				registry.add("bootstrap.testcontainers.containers.redis2", () -> "redis:7.4.0");
			}
		}
	}

	@Nested
	class EnabledFalse extends AbstractOneTestIT {
		@DynamicPropertySource
		static void properties(final DynamicPropertyRegistry registry) {
			registry.add("bootstrap.testcontainers.enabled", () -> "false");
		}
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class None extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) { /* empty */ }
		}
		@Nested
		@ContextConfiguration(initializers={BootstrapTestContainersApplicationContextInitializer.class})
		class Two extends AbstractOneTestIT {
			@DynamicPropertySource
			static void properties(final DynamicPropertyRegistry registry) {
//				registry.add("bootstrap.testcontainers.containers.redis1", () -> "redis:7.4.0");
//				registry.add("bootstrap.testcontainers.containers.redis2", () -> "redis:7.4.0");
			}
		}
	}
}
