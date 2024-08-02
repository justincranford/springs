package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

@SuppressWarnings({"nls", "resource"})
public class TestContainerRedis {
	private static final String IMAGE_NAME_VERSION = "redis:7.4.0"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "redis";
	private static final Integer REDIS_PORT = Integer.valueOf(6379);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final GenericContainer<?> INSTANCE = new GenericContainer<>(IMAGE_NAME_VERSION)
		.withReuse(true)
		.withExposedPorts(REDIS_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
