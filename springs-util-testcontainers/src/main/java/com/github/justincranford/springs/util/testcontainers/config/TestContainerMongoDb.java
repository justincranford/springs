package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

@SuppressWarnings({"nls", "resource"})
public class TestContainerMongoDb {
	private static final String IMAGE_NAME_VERSION = "mongo:7.0.12"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "mongo";
	private static final Integer MONGODB_PORT = Integer.valueOf(27017);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final MongoDBContainer INSTANCE = new MongoDBContainer(IMAGE_NAME_VERSION)
		.withReuse(true)
		.withExposedPorts(MONGODB_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
