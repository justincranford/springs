package com.github.justincranford.springs.util.testcontainers.bootstrap;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;

@NoArgsConstructor(access= AccessLevel.PRIVATE)
@SuppressWarnings({"unused", "checkstyle:UtilityClass"})
public class BootstrapTestContainersEnvironmentPostProcessor implements EnvironmentPostProcessor {
    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment configurableEnvironment, final SpringApplication springApplication) {
        BootstrapTestContainers.bootstrap(configurableEnvironment);
    }
}
