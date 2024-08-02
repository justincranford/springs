package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

@SuppressWarnings({"nls", "resource"})
public class TestContainerPostgresql {
	private static final String IMAGE_NAME_VERSION = "postgres:16.3"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "postgresql";
	private static final Integer POSTGRESQL_PORT = PostgreSQLContainer.POSTGRESQL_PORT;
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final PostgreSQLContainer<?> INSTANCE = new PostgreSQLContainer<>(IMAGE_NAME_VERSION)
		.withReuse(true)
		.withExposedPorts(POSTGRESQL_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
            .withStrategy(Wait.forLogMessage(".*database system is ready to accept connections.*\\s", 2))
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
