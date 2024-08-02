package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;

import org.testcontainers.containers.GenericContainer;

import io.micrometer.observation.annotation.Observed;

// Container.start() is blocking, so start containers concurrently
// TODO Make @Observed work
@SuppressWarnings({"nls", "boxing"})
public class SpringsUtilTestContainers {
	private static final List<GenericContainer<?>> ALL_TEST_CONTAINER_INSTANCES = List.of(
		TestContainerElasticsearch.INSTANCE,	// Example: 23.152 seconds
		TestContainerKeycloak.INSTANCE,			// Example: 18.809 seconds
		TestContainerGrafana.INSTANCE,			// Example: 10.437 seconds
		TestContainerKafka.INSTANCE,			// Example:  8.321 seconds
		TestContainerZipkin.INSTANCE,			// Example:  6.794 seconds
		TestContainerDynamoDb.INSTANCE,			// Example:  6.3 seconds
		TestContainerPostgresql.INSTANCE,		// Example:  6.204 seconds
		TestContainerSeleniumChrome.INSTANCE,	// Example:  5.468 seconds
		TestContainerMongoDb.INSTANCE,			// Example:  5.06 seconds
		TestContainerVault.INSTANCE,			// Example:  3.64 seconds
		TestContainerConsul.INSTANCE,			// Example:  2.602 seconds
		TestContainerRedis.INSTANCE,			// Example:  2.334 seconds
		TestContainerOllama.INSTANCE			// Example:  1.318 seconds
	);

	@Observed
	public static void startAllContainers() {
		startContainers(ALL_TEST_CONTAINER_INSTANCES);
	}

	@Observed
	public static void stopAllContainers() {
		stopContainers(ALL_TEST_CONTAINER_INSTANCES);
	}

	@Observed
	public static void startContainers(final List<GenericContainer<?>> testContainerInstances) {
		final long startNanos = System.nanoTime();
		try {
			System.out.println(String.format("Starting containers, count: %s", testContainerInstances.size()));
			testContainerInstances.parallelStream().forEach(container -> startContainer(container));
		} finally {
			System.out.println(String.format("Started containers, count: %s, duration: %s", testContainerInstances.size(), format(startNanos)));
		}
	}

	@Observed
	public static void stopContainers(final List<GenericContainer<?>> testContainerInstances) {
		final long startNanos = System.nanoTime();
		try {
			System.out.println(String.format("Stopping containers, count: %s", ALL_TEST_CONTAINER_INSTANCES.size()));
			testContainerInstances.parallelStream().forEach(container -> stopContainer(container));
		} finally {
			System.out.println(String.format("Stopped containers, count: %s, duration: %s", ALL_TEST_CONTAINER_INSTANCES.size(), format(startNanos)));
		}
	}

	@Observed
	private static boolean startContainer(final GenericContainer<?> container) {
		final long startNanos = System.nanoTime();
		final boolean isStarted = container.isRunning();
		if (isStarted) {
			System.out.println(String.format("Already started container, image name: %s", container.getDockerImageName()));
		} else {
			try {
				System.out.println(String.format("Starting container, image name: %s", container.getDockerImageName()));
				container.start();
			} finally {
				System.out.println(String.format("Started container, image name: %s, duration: %s", container.getDockerImageName(), format(startNanos)));
			}
		}
		return isStarted;
	}

	@Observed
	private static boolean stopContainer(final GenericContainer<?> container) {
		final long startNanos = System.nanoTime();
		final boolean isStopped = !container.isRunning();
		if (isStopped) {
			System.out.println(String.format("Already stopped container, image name: %s", container.getDockerImageName()));
		} else {
			try {
				System.out.println(String.format("Stopping container, image name: %s", container.getDockerImageName()));
				container.stop();
			} finally {
				System.out.println(String.format("Stopped container, image name: %s, duration: %s", container.getDockerImageName(), format(startNanos)));
			}
		}
		return isStopped;
	}

	private static String format(final long startNanos) {
		return Duration.ofNanos(System.nanoTime() - startNanos).truncatedTo(ChronoUnit.MILLIS).toMillis()/1000F + " seconds";
	}
}
