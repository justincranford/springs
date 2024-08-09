package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.ollama.OllamaContainer;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerOllama extends AbstractTestContainer<OllamaContainer> {
	public static final String DOCKER_IMAGE_NAME = "ollama/ollama:0.3.2"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "ollama";
	private static final Integer OLLAMA_PORT = Integer.valueOf(11434);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	public OllamaContainer initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new OllamaContainer(dockerImageName)
					.withReuse(true)
					.withExposedPorts(OLLAMA_PORT)
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
