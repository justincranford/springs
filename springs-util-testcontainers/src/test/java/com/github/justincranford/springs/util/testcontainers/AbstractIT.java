package com.github.justincranford.springs.util.testcontainers;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.test.context.ActiveProfiles;

import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;
import com.github.justincranford.springs.util.testcontainers.containers.AbstractTestContainer;

import io.micrometer.observation.annotation.Observed;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@EnableAutoConfiguration
@SpringBootTest(classes={SpringsUtilTestContainers.class})
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@Observed
@SuppressWarnings({"nls", "static-method", "resource"})
public class AbstractIT {
	@BeforeEach
	private void beforeEach() {
		for (final AbstractTestContainer<?> testContainer : containersList()) {
			verifyStopped(testContainer);
		}
	}

	@AfterEach
	private void afterEach() {
		SpringsUtilTestContainers.stopContainers(containersList());
		for (final AbstractTestContainer<?> testContainer : containersList()) {
			verifyStopped(testContainer);
		}
	}

	@Autowired
    private ApplicationContext applicationContext;

	public static Stream<AbstractTestContainer<?>> containersStream() {
		return containersList().stream();
	}

	protected void verifyStopped(final AbstractTestContainer<?> testContainer) {
		assertThat(testContainer).isNotNull();
		assertThat(testContainer.getInstance()).isNotNull();
		assertThat(testContainer.getInstance().isRunning()).isFalse();
	}

	protected void verifyStarted(final AbstractTestContainer<?> testContainer) {
		assertThat(testContainer).isNotNull();
		assertThat(testContainer.getInstance()).isNotNull();
		assertThat(testContainer.getInstance().isRunning()).isTrue();
		assertThat(testContainer.getInstance().getHost()).isNotNull();
		assertThat(testContainer.getInstance().getFirstMappedPort()).isNotNull();
		assertThat(testContainer.getInstance().getContainerName()).isNotNull();
		log.info("Host: {}, Port: {}, Name: {}", testContainer.getInstance().getHost(), testContainer.getInstance().getFirstMappedPort(), testContainer.getContainerName());
	}

	public static List<AbstractTestContainer<?>> containersList() {
//		return SpringsUtilTestContainers.ALL;
		return List.of(
//			SpringsUtilTestContainers.ELASTICSEARCH,
//			SpringsUtilTestContainers.KEYCLOCK,
//			SpringsUtilTestContainers.GRAFANA,
//			SpringsUtilTestContainers.KAFKA,
//			SpringsUtilTestContainers.ZIPKIN,
//			SpringsUtilTestContainers.DYNAMODB,
//			SpringsUtilTestContainers.POSTGRESQL,
//			SpringsUtilTestContainers.SELENIUMCHROME,
//			SpringsUtilTestContainers.MONGODB,
			SpringsUtilTestContainers.VAULT,
			SpringsUtilTestContainers.CONSUL,
			SpringsUtilTestContainers.REDIS,
			SpringsUtilTestContainers.OLLAMA
		);
	}
}
