package com.github.justincranford.springs.server.authentication;

import com.github.justincranford.springs.server.authentication.config.SpringsServerAuthenticationConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.TlsEnabledByDefaultApplicationContextInitializer;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({SpringsServerAuthenticationConfiguration.class})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class SpringsServerAuthenticationMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsServerAuthenticationMain.class);
		springApplication.addInitializers(new TlsEnabledByDefaultApplicationContextInitializer());
		springApplication.run(args);
	}
}
