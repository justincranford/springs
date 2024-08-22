package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerZipkin extends AbstractTestContainer<GenericContainer<?>> {
	public static final String DOCKER_IMAGE_NAME = "openzipkin/zipkin:3.4"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "zipkin";
	private static final Integer ZIPKIN_PORT = Integer.valueOf(9411);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(30);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public GenericContainer<?> initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new GenericContainer<>(dockerImageName)
			        .withReuse(true)
			        .withExposedPorts(ZIPKIN_PORT)
			        .waitingFor(Wait.forHttp("/api/v2/spans?serviceName=anything").withStartupTimeout(START_TIMEOUT))
			        .withNetwork(Network.SHARED)
			        .withNetworkAliases(NETWORK_ALIAS);
		} catch (Throwable t) {
			log.debug("Failed to initialize", t);
			super.instance = null;
		}
		return super.instance;
	}
}
