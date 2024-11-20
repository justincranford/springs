package com.github.justincranford.springs.util.https.server.initializer;

import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

@NoArgsConstructor
@SuppressWarnings({"unused"})
public final class TlsEnabledByDefaultApplicationContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Override
    public void initialize(final ConfigurableApplicationContext configurableApplicationContext) {
		TlsEnabledByDefault.generateTlsKeyMaterialAndPrependAsNewPropertySources(configurableApplicationContext.getEnvironment());
	}
}
