package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.MongoDBContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerMongoDb extends AbstractTestContainer<MongoDBContainer> {
	public static final String DOCKER_IMAGE_NAME = "mongo:7.0.12"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "mongo";
	private static final Integer MONGODB_PORT = Integer.valueOf(27017);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	public MongoDBContainer initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new MongoDBContainer(dockerImageName)
					.withReuse(true)
					.withExposedPorts(MONGODB_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
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
