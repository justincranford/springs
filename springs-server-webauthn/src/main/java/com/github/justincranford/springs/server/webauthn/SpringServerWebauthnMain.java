package com.github.justincranford.springs.server.webauthn;

import com.github.justincranford.springs.server.webauthn.config.SpringsServerWebauthnConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.BootstrapTlsApplicationContextInitializer;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({SpringsServerWebauthnConfiguration.class})
public class SpringServerWebauthnMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringServerWebauthnMain.class);
		springApplication.addInitializers(new BootstrapTlsApplicationContextInitializer());
		springApplication.addInitializers(new BootstrapTestContainersApplicationContextInitializer());
		springApplication.run(args);
	}
}
