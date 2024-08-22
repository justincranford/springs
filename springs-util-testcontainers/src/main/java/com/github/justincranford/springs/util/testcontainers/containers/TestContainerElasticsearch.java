package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.elasticsearch.ElasticsearchContainer;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerElasticsearch extends AbstractTestContainer<ElasticsearchContainer> {
	public static final String DOCKER_IMAGE_NAME = "elasticsearch:8.14.3"; // Last checked on 2024-08-01
//	public static final String DOCKER_IMAGE_NAME = "elasticsearch:7.17.23"; // 2019-04-10

	private static final String NETWORK_ALIAS = "elastic";
    private static final Integer ELASTICSEARCH_HTTP_PORT = Integer.valueOf(9200);
    private static final Integer ELASTICSEARCH_TRANSPORT_PORT = Integer.valueOf(9300);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(60);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public ElasticsearchContainer initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new ElasticsearchContainer(dockerImageName)
					.withReuse(true)
					.withExposedPorts(ELASTICSEARCH_HTTP_PORT, ELASTICSEARCH_TRANSPORT_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
			            .withStrategy(new LogMessageWaitStrategy().withRegEx(".*(\"message\":\\s?\"started[\\s?|\"].*|] started\n$)"))
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
