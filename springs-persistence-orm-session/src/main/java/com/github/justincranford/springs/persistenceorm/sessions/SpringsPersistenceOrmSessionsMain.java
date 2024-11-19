package com.github.justincranford.springs.persistenceorm.sessions;

import com.github.justincranford.springs.persistenceorm.config.SpringsPersistenceOrmSessionsConfiguration;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.https.server.initializer.TlsEnabledByDefaultInitializer;

@SpringBootApplication
@Import({ SpringsPersistenceOrmSessionsConfiguration.class})
@SuppressWarnings({"resource"})
public class SpringsPersistenceOrmSessionsMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsPersistenceOrmSessionsMain.class);
		springApplication.addInitializers(new TlsEnabledByDefaultInitializer());
		springApplication.run(args);
	}
}
