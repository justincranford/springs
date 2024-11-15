package com.github.justincranford.springs.persistenceorm.sessions;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.persistenceorm.sessions.config.SpringsPersistenceOrmSessionsConfiguration;
import com.github.justincranford.springs.util.https.server.initializer.TlsInitializer;

@SpringBootApplication
@Import({SpringsPersistenceOrmSessionsConfiguration.class})
@SuppressWarnings({"resource"})
public class SpringsPersistenceOrmSessionsMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsPersistenceOrmSessionsMain.class);
		springApplication.addInitializers(new TlsInitializer());
		springApplication.run(args);
	}
}
