package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerPostgresql extends AbstractTestContainer<PostgreSQLContainer<?>> {
	public static final String DOCKER_IMAGE_NAME = "postgres:16.3"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "postgresql";
	private static final Integer POSTGRESQL_PORT = PostgreSQLContainer.POSTGRESQL_PORT;
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public PostgreSQLContainer<?> initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new PostgreSQLContainer<>(dockerImageName)
					.withReuse(true)
					.withExposedPorts(POSTGRESQL_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
			            .withStrategy(Wait.forLogMessage(".*database system is ready to accept connections.*\\s", 2))
			            .withStrategy(Wait.forListeningPort())
			        )
				    .withNetwork(Network.SHARED)
				    .withNetworkAliases(NETWORK_ALIAS);
		} catch (Throwable t) {
			log.debug("Failed to initialize", t);
			super.instance = null;
		}
		return super.instance;
	}
}
