package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerVault extends AbstractTestContainer<VaultContainer<?>> {
	public static final String DOCKER_IMAGE_NAME = "hashicorp/vault:1.17.2"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "hashicorp";
	private static final Integer VAULT_PORT = Integer.valueOf(8200);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public VaultContainer<?> getInstance() {
		initializeIfRequired();
		return super.instance;
	}

	@Override
	public void initializeIfRequired() {
		if (!super.initialized) {
			try {
				final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
				super.instance = new VaultContainer<>(dockerImageName)
					.withReuse(true)
					.withExposedPorts(VAULT_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
			    		.withStrategy(Wait.forHttp("/v1/sys/health").forStatusCode(200))
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
