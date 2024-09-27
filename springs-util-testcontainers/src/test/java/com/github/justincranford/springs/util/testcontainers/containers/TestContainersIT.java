package com.github.justincranford.springs.util.testcontainers.containers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import com.github.justincranford.springs.util.testcontainers.AbstractIT;
import com.github.justincranford.springs.util.testcontainers.config.SpringsUtilTestContainers;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class TestContainersIT extends AbstractIT {
	@ParameterizedTest
	@MethodSource("containersStream")
	void testStopStartContainer(final AbstractTestContainer<?> testContainer) {
		SpringsUtilTestContainers.startContainer(testContainer);
		super.verifyStarted(testContainer);

		SpringsUtilTestContainers.stopContainer(testContainer);
		super.verifyStopped(testContainer);

		SpringsUtilTestContainers.startContainer(testContainer);
		super.verifyStarted(testContainer);
	}

	@Test
	void testStopStartContainers() {
		SpringsUtilTestContainers.startContainers(containersList());
		for (final AbstractTestContainer<?> testContainer : containersList()) {
			super.verifyStarted(testContainer);
		}

		SpringsUtilTestContainers.stopContainers(containersList());
		for (final AbstractTestContainer<?> testContainer : containersList()) {
			super.verifyStopped(testContainer);
		}

		SpringsUtilTestContainers.startContainers(containersList());
		for (final AbstractTestContainer<?> testContainer : containersList()) {
			super.verifyStarted(testContainer);
		}
	}
}
