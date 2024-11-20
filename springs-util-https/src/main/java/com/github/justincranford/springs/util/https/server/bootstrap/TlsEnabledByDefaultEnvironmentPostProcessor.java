package com.github.justincranford.springs.util.https.server.bootstrap;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;

@NoArgsConstructor(access= AccessLevel.PRIVATE)
@SuppressWarnings({"unused"})
public final class TlsEnabledByDefaultEnvironmentPostProcessor implements EnvironmentPostProcessor {
    @Override
    public void postProcessEnvironment(final ConfigurableEnvironment configurableEnvironment, final SpringApplication springApplication) {
        TlsEnabledByDefault.generateTlsKeyMaterialAndPrependAsNewPropertySources(configurableEnvironment);
    }
}
