package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.consul.ConsulContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource", "boxing"})
public class TestContainerConsul extends AbstractTestContainer<ConsulContainer>  {
	public static final String DOCKER_IMAGE_NAME = "hashicorp/consul:1.19.1"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "hashicorp";
	private static final Integer CONSUL_HTTP_PORT = Integer.valueOf(8500);
	private static final Integer CONSUL_GRPC_PORT = Integer.valueOf(8502);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public ConsulContainer initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new ConsulContainer(dockerImageName)
					.withReuse(true)
					.withExposedPorts(CONSUL_HTTP_PORT, CONSUL_GRPC_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
			            .withStrategy(Wait.forHttp("/v1/status/leader").forPort(CONSUL_HTTP_PORT).forStatusCode(200))
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
