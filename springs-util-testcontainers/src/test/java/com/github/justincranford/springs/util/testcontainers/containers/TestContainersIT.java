package com.github.justincranford.springs.util.testcontainers.containers;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.justincranford.springs.util.testcontainers.AbstractIT;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "static-method", "resource"})
public class TestContainersIT extends AbstractIT {
	public static Stream<AbstractTestContainer<?>> args() {
		return Stream.of(
				SpringsUtilTestContainers.CONSUL,
				SpringsUtilTestContainers.VAULT,
				SpringsUtilTestContainers.REDIS
		);
	}

	@ParameterizedTest
	@MethodSource("args")
	void testStopStartContainer(final AbstractTestContainer<?> testContainer) {
		assertThat(testContainer).isNotNull();
		assertThat(testContainer.getInstance()).isNotNull();
		assertThat(testContainer.isRunning()).isTrue();
		assertThat(testContainer.getInstance().getHost()).isNotNull();
		assertThat(testContainer.getInstance().getFirstMappedPort()).isNotNull();
		log.info("Host: {}, Port: {}", testContainer.getInstance().getHost(), testContainer.getInstance().getFirstMappedPort());

		SpringsUtilTestContainers.stopContainer(testContainer);
		assertThat(testContainer.isRunning()).isFalse();

		SpringsUtilTestContainers.startContainer(testContainer);
		assertThat(testContainer.isRunning()).isTrue();
		assertThat(testContainer.getInstance().getHost()).isNotNull();
		assertThat(testContainer.getInstance().getFirstMappedPort()).isNotNull();
		log.info("Host: {}, Port: {}", testContainer.getInstance().getHost(), testContainer.getInstance().getFirstMappedPort());
	}

	@Test
	void testStopStartContainers() {
		args().forEach(testContainer -> {
			assertThat(testContainer).isNotNull();
			assertThat(testContainer.getInstance()).isNotNull();
			assertThat(testContainer.isRunning()).isTrue();
			assertThat(testContainer.getInstance().getHost()).isNotNull();
			assertThat(testContainer.getInstance().getFirstMappedPort()).isNotNull();
			log.info("Host: {}, Port: {}", testContainer.getInstance().getHost(), testContainer.getInstance().getFirstMappedPort());
		});

		SpringsUtilTestContainers.stopContainers(args().toList());
		args().forEach(testContainer -> {
			assertThat(testContainer.isRunning()).isFalse();
		});

		SpringsUtilTestContainers.startContainers(args().toList());
		args().forEach(testContainer -> {
			assertThat(testContainer.isRunning()).isTrue();
			assertThat(testContainer.getInstance().getHost()).isNotNull();
			assertThat(testContainer.getInstance().getFirstMappedPort()).isNotNull();
			log.info("Host: {}, Port: {}", testContainer.getInstance().getHost(), testContainer.getInstance().getFirstMappedPort());
		});
	}
}
