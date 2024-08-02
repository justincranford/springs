package com.github.justincranford.springs.util.testcontainers.config;

import java.time.Duration;

import org.openqa.selenium.chrome.ChromeOptions;
import org.testcontainers.containers.BrowserWebDriverContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;

@SuppressWarnings({"nls", "resource"})
public class TestContainerSeleniumChrome {
	private static final String IMAGE_NAME_VERSION = "selenium/standalone-chrome:127.0"; // Last checked on 2024-08-01
	private static final String NETWORK_ALIAS = "selenium";
	private static final Integer SELENIUM_PORT = Integer.valueOf(4444);
    private static final Integer VNC_PORT = Integer.valueOf(5900);
	private static final Duration START_TIMEOUT = Duration.ofSeconds(15);

	public static final BrowserWebDriverContainer<?> INSTANCE = new BrowserWebDriverContainer<>(IMAGE_NAME_VERSION)
		.withCapabilities(new ChromeOptions())
		.withExposedPorts(SELENIUM_PORT, VNC_PORT)
	    .waitingFor(new WaitAllStrategy(WaitAllStrategy.Mode.WITH_MAXIMUM_OUTER_TIMEOUT).withStartupTimeout(START_TIMEOUT)
    		.withStrategy(new LogMessageWaitStrategy().withRegEx(".*(RemoteWebDriver instances should connect to|Selenium Server is up and running|Started Selenium Standalone).*\n"))
            .withStrategy(Wait.forListeningPort())
        )
	    .withNetwork(Network.SHARED)
	    .withNetworkAliases(NETWORK_ALIAS);
}
