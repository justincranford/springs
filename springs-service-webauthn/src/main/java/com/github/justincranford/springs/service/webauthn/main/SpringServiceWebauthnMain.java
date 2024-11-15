package com.github.justincranford.springs.service.webauthn.main;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.webauthn.config.SpringsServiceWebauthnConfiguration;
import com.github.justincranford.springs.util.https.server.TlsInitializer;

@SpringBootApplication
@Import({SpringsServiceWebauthnConfiguration.class})
@SuppressWarnings({"resource"})
public class SpringServiceWebauthnMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringServiceWebauthnMain.class);
		springApplication.addInitializers(new TlsInitializer());
		springApplication.run(args);
	}
}
