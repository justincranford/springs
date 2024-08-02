package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

import dasniko.testcontainers.keycloak.KeycloakContainer;

@SuppressWarnings({"nls", "resource", "boxing"})
public class TestContainerKeycloak {
	private static final String IMAGE_NAME_VERSION = "keycloak/keycloak:25.0.2"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "keycloak";
//    private static final Integer KEYCLOAK_PORT_HTTP = Integer.valueOf(8080);
//    private static final Integer KEYCLOAK_PORT_HTTPS = Integer.valueOf(8443);
//    private static final Integer KEYCLOAK_PORT_DEBUG = Integer.valueOf(8787);
//    private static final Integer KEYCLOAK_PORT_MGMT = Integer.valueOf(9000);
//	private static final Duration START_TIMEOUT = Duration.ofSeconds(120);

	public static final KeycloakContainer INSTANCE = new KeycloakContainer(IMAGE_NAME_VERSION)
//		.withReuse(true)
//        .withExposedPorts(KEYCLOAK_PORT_HTTP, KEYCLOAK_PORT_HTTPS, KEYCLOAK_PORT_MGMT)
////		.withExposedPorts(KEYCLOAK_PORT_HTTP, KEYCLOAK_PORT_HTTPS, KEYCLOAK_PORT_DEBUG, KEYCLOAK_PORT_MGMT)
//	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
//    		.withStrategy(Wait.forHttp("/health/started").forPort(KEYCLOAK_PORT_MGMT))//.usingTls().allowInsecure())
//            .withStrategy(Wait.forListeningPort())
//        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
