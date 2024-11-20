package com.github.justincranford.springs.persistenceredis.sessions;

import com.github.justincranford.springs.persistenceorm.config.SpringsPersistenceOrmSessionsConfiguration;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.https.server.initializer.TlsEnabledByDefaultInitializer;

@SpringBootApplication
@Import({ SpringsPersistenceOrmSessionsConfiguration.class})
@NoArgsConstructor(access=AccessLevel.PRIVATE)
public final class SpringsPersistenceOrmSessionsMain {
	public static void main(final String[] args) {
		final SpringApplication springApplication = new SpringApplication(SpringsPersistenceOrmSessionsMain.class);
		springApplication.addInitializers(new TlsEnabledByDefaultInitializer());
		springApplication.run(args);
	}
}
