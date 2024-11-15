package com.github.justincranford.springs.server.webauthn;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.server.webauthn.config.SpringsServiceWebauthnConfiguration;
import com.github.justincranford.springs.util.https.server.initializer.TlsEnabledByDefaultInitializer;

@SpringBootApplication
@Import({SpringsServiceWebauthnConfiguration.class})
@SuppressWarnings({"resource"})
public class SpringServiceWebauthnMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringServiceWebauthnMain.class);
		springApplication.addInitializers(new TlsEnabledByDefaultInitializer());
		springApplication.run(args);
	}
}
