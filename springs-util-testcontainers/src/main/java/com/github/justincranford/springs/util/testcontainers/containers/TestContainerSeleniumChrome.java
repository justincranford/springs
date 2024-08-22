package com.github.justincranford.springs.util.testcontainers.containers;

import java.time.Duration;

import org.openqa.selenium.chrome.ChromeOptions;
import org.testcontainers.containers.BrowserWebDriverContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.utility.DockerImageName;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls", "resource"})
public class TestContainerSeleniumChrome extends AbstractTestContainer<BrowserWebDriverContainer<?>> {
	public static final String DOCKER_IMAGE_NAME = "selenium/standalone-chrome:127.0"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "selenium";
	private static final Integer SELENIUM_PORT = Integer.valueOf(4444);
    private static final Integer VNC_PORT = Integer.valueOf(5900);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	@Override
	public String getContainerName() {
		return DOCKER_IMAGE_NAME;
	}

	@Override
	public BrowserWebDriverContainer<?> initAndGetInstance() {
		try {
			final DockerImageName dockerImageName = DockerImageName.parse(DOCKER_IMAGE_NAME);
			super.instance = new BrowserWebDriverContainer<>(dockerImageName)
					.withCapabilities(new ChromeOptions())
					.withExposedPorts(SELENIUM_PORT, VNC_PORT)
				    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
			    		.withStrategy(new LogMessageWaitStrategy().withRegEx(".*(RemoteWebDriver instances should connect to|Selenium Server is up and running|Started Selenium Standalone).*\n"))
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
