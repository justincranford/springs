package com.github.justincranford.springs.persistenceredis.sessions;

import com.github.justincranford.springs.persistenceorm.config.SpringsPersistenceOrmSessionsConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.BootstrapTlsApplicationContextInitializer;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

@SpringBootApplication
@Import({ SpringsPersistenceOrmSessionsConfiguration.class})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class SpringsPersistenceOrmSessionsMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsPersistenceOrmSessionsMain.class);
		springApplication.addInitializers(new BootstrapTlsApplicationContextInitializer());
		springApplication.run(args);
	}
}
