package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;

@SuppressWarnings({"nls", "resource"})
public class TestContainerZipkin {
	private static final String IMAGE_NAME_VERSION = "openzipkin/zipkin:3.4"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "zipkin";
	private static final Integer ZIPKIN_PORT = Integer.valueOf(9411);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final GenericContainer<?> INSTANCE = new GenericContainer<>(IMAGE_NAME_VERSION)
        .withReuse(true)
        .withExposedPorts(ZIPKIN_PORT)
        .waitingFor(Wait.forHttp("/api/v2/spans?serviceName=anything").withStartupTimeout(START_TIMEOUT))
        .withNetwork(Network.SHARED)
        .withNetworkAliases(NETWORK_ALIAS);
}
