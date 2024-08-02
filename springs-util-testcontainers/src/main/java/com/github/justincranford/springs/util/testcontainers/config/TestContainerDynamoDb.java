package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

@SuppressWarnings({"nls", "resource"})
public class TestContainerDynamoDb {
	private static final String IMAGE_NAME_VERSION = "amazon/dynamodb-local:2.5.2"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "dynamodb";
	private static final Integer DYNAMODB_PORT = Integer.valueOf(8000);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final GenericContainer<?> INSTANCE = new GenericContainer<>(IMAGE_NAME_VERSION)
		.withReuse(true)
		.withExposedPorts(DYNAMODB_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
