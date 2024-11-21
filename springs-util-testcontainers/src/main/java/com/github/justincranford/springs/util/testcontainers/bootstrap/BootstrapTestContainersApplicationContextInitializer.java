package com.github.justincranford.springs.util.testcontainers.bootstrap;

import lombok.NoArgsConstructor;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

@NoArgsConstructor
@SuppressWarnings({"unused", "checkstyle:UtilityClass"})
public class BootstrapTestContainersApplicationContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Override
    public void initialize(final ConfigurableApplicationContext configurableApplicationContext) {
        BootstrapTestContainers.bootstrap(configurableApplicationContext.getEnvironment());
	}
}
