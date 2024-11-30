package com.github.justincranford.springs.persistenceredis;

import com.github.justincranford.springs.persistenceredis.config.SpringsPersistenceRedisSessionsConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.BootstrapTlsApplicationContextInitializer;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({ SpringsPersistenceRedisSessionsConfiguration.class})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class SpringsPersistenceRedisSessionsMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsPersistenceRedisSessionsMain.class);
		springApplication.addInitializers(new BootstrapTlsApplicationContextInitializer());
		springApplication.run(args);
	}
}
