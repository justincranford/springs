package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.grafana.LgtmStackContainer;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerGrafana extends AbstractTestContainer<LgtmStackContainer> {
	public static final String DOCKER_IMAGE_NAME = "grafana/otel-lgtm:0.6.0"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "grafana";
	private static final Integer GRAFANA_PORT = Integer.valueOf(3000);
	private static final Integer OTLP_GRPC_PORT = Integer.valueOf(4317);
	private static final Integer OTLP_HTTP_PORT = Integer.valueOf(4318);
	private static final Integer PROMETHEUS_PORT = Integer.valueOf(9090);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(30);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public LgtmStackContainer getInstance() {
		initializeIfRequired();
		return super.instance;
	}

	@Override
	public void initializeIfRequired() {
		if (!super.initialized) {
			try {
				final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
				super.instance = new LgtmStackContainer(dockerImageName)
					.withReuse(true)
					.withExposedPorts(GRAFANA_PORT, OTLP_GRPC_PORT, OTLP_HTTP_PORT, PROMETHEUS_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
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
