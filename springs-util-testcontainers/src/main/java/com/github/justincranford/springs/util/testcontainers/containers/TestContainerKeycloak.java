package com.github.justincranford.springs.util.testcontainers.containers;

import org.testcontainers.containers.Network;
import org.testcontainers.utility.DockerImageName;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public final class TestContainerKeycloak extends AbstractTestContainer<KeycloakContainer> {
	public static final String DOCKER_IMAGE_NAME = "keycloak/keycloak:25.0.2"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "keycloak";
//    private static final Integer KEYCLOAK_PORT_HTTP = Integer.valueOf(8080);
//    private static final Integer KEYCLOAK_PORT_HTTPS = Integer.valueOf(8443);
//    private static final Integer KEYCLOAK_PORT_DEBUG = Integer.valueOf(8787);
//    private static final Integer KEYCLOAK_PORT_MGMT = Integer.valueOf(9000);
//    private static final Duration START_TIMEOUT = Duration.ofSeconds(120);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public KeycloakContainer initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new KeycloakContainer(dockerImageName.asCanonicalNameString())
//					.withReuse(true)
//			        .withExposedPorts(KEYCLOAK_PORT_HTTP, KEYCLOAK_PORT_HTTPS, KEYCLOAK_PORT_MGMT)
////					.withExposedPorts(KEYCLOAK_PORT_HTTP, KEYCLOAK_PORT_HTTPS, KEYCLOAK_PORT_DEBUG, KEYCLOAK_PORT_MGMT)
//				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
//			    		.withStrategy(Wait.forHttp("/health/started").forPort(KEYCLOAK_PORT_MGMT))//.usingTls().allowInsecure())
//			            .withStrategy(Wait.forListeningPort())
//			        )
					    .withNetwork(Network.SHARED)
					    .withNetworkAliases(NETWORK_ALIAS);
		} catch (Throwable t) {
			log.debug("Failed to initialize", t);
			super.instance = null;
		}
		return super.instance;
	}
}
