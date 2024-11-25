package com.github.justincranford.springs.persistenceredis.sessions.config;

import com.github.justincranford.springs.persistenceorm.clients.config.SpringsPersistenceOrmClientsConfiguration;
import com.github.justincranford.springs.persistenceorm.clients.config.SpringsPersistenceOrmSessionsClientSessionsConfiguration;
import com.github.justincranford.springs.server.authentication.encoding.config.SpringsPersistenceOrmSessionsUserSessionsConfiguration;
import com.github.justincranford.springs.server.authentication.encoding.config.SpringsPersistenceOrmUsersConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
	SpringsPersistenceOrmUsersConfiguration.class,
	SpringsPersistenceOrmClientsConfiguration.class,
	SpringsPersistenceOrmSessionsUserSessionsConfiguration.class,
	SpringsPersistenceOrmSessionsClientSessionsConfiguration.class
})
public class SpringsPersistenceOrmSessionsSessionsConfiguration {
	// do nothing
}
