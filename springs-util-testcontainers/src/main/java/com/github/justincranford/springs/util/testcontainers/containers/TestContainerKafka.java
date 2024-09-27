package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.KafkaContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerKafka extends AbstractTestContainer<KafkaContainer> {
	public static final String DOCKER_IMAGE_NAME = "confluentinc/cp-kafka:7.7.0"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "kafka";
	private static final Integer KAFKA_PORT = Integer.valueOf(9093);
	private static final Integer ZOOKEEPER_PORT = Integer.valueOf(2181);
   	private static final Duration START_TIMEOUT = Duration.ofSeconds(30);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public KafkaContainer getInstance() {
		initializeIfRequired();
		return super.instance;
	}

	@Override
   	public void initializeIfRequired() {
		if (!super.initialized) {
			try {
				final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
				super.instance = new KafkaContainer(dockerImageName)
					.withReuse(true)
					.withExposedPorts(KAFKA_PORT, ZOOKEEPER_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
			    		.withStrategy(Wait.forLogMessage(".*\\[KafkaServer id=\\d+\\] started.*", 1))
			            .withStrategy(Wait.forListeningPort())
			        )
				    .withNetwork(Network.SHARED)
				    .withNetworkAliases(NETWORK_ALIAS);
			} catch (Throwable t) {
				log.debug("Failed to initialize", t);
				super.instance = null;
			} finally {
				this.initialized = true;
			}
		}
	}
}
