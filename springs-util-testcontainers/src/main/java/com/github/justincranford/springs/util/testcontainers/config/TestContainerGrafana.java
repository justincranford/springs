package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.grafana.LgtmStackContainer;

@SuppressWarnings({"nls", "resource"})
public class TestContainerGrafana {
	private static final String IMAGE_NAME_VERSION = "grafana/otel-lgtm:0.6.0"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "grafana";
	private static final Integer GRAFANA_PORT = Integer.valueOf(3000);
	private static final Integer OTLP_GRPC_PORT = Integer.valueOf(4317);
	private static final Integer OTLP_HTTP_PORT = Integer.valueOf(4318);
	private static final Integer PROMETHEUS_PORT = Integer.valueOf(9090);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final LgtmStackContainer INSTANCE = new LgtmStackContainer(IMAGE_NAME_VERSION)
		.withReuse(true)
		.withExposedPorts(GRAFANA_PORT, OTLP_GRPC_PORT, OTLP_HTTP_PORT, PROMETHEUS_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
