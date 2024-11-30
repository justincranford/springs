package com.github.justincranford.springs.util.https.server.bootstrap;

import lombok.NoArgsConstructor;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;

@NoArgsConstructor
@SuppressWarnings({"unused"})
public final class BootstrapTlsApplicationContextInitializer implements ApplicationContextInitializer<ConfigurableApplicationContext> {
    @Override
    public void initialize(final ConfigurableApplicationContext configurableApplicationContext) {
		BootstrapTls.generateTlsKeyMaterialAndPrependAsNewPropertySources(configurableApplicationContext.getEnvironment());
	}
}
