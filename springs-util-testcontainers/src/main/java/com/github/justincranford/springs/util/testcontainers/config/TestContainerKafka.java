package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

@SuppressWarnings({"nls", "resource"})
public class TestContainerKafka {
	private static final String IMAGE_NAME_VERSION = "confluentinc/cp-kafka:7.7.0"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "kafka";
	private static final Integer KAFKA_PORT = Integer.valueOf(9093);
	private static final Integer ZOOKEEPER_PORT = Integer.valueOf(2181);
   	private static final Duration START_TIMEOUT = Duration.ofSeconds(30);

   	public static final KafkaContainer INSTANCE = new KafkaContainer(DockerImageName.parse(IMAGE_NAME_VERSION))
		.withReuse(true)
		.withExposedPorts(KAFKA_PORT, ZOOKEEPER_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
    		.withStrategy(Wait.forLogMessage(".*\\[KafkaServer id=\\d+\\] started.*", 1))
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
