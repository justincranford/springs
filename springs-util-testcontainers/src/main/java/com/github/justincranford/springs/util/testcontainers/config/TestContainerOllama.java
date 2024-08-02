package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.ollama.OllamaContainer;
import org.testcontainers.utility.DockerImageName;

@SuppressWarnings({"nls", "resource"})
public class TestContainerOllama {
	private static final String IMAGE_NAME_VERSION = "ollama/ollama:0.3.2"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "ollama";
	private static final Integer OLLAMA_PORT = Integer.valueOf(11434);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final OllamaContainer INSTANCE = new OllamaContainer(DockerImageName.parse(IMAGE_NAME_VERSION))
		.withReuse(true)
		.withExposedPorts(OLLAMA_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
