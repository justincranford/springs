package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.vault.VaultContainer;

@SuppressWarnings({"nls", "resource"})
public class TestContainerVault {
	private static final String IMAGE_NAME_VERSION = "hashicorp/vault:1.17.2"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "hashicorp";
	private static final Integer VAULT_PORT = Integer.valueOf(8200);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final VaultContainer<?> INSTANCE = new VaultContainer<>(DockerImageName.parse(IMAGE_NAME_VERSION))
		.withReuse(true)
		.withExposedPorts(VAULT_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
    		.withStrategy(Wait.forHttp("/v1/sys/health").forStatusCode(200))
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
