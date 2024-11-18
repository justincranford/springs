package com.github.justincranford.springs.persistenceorm.sessions.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.persistenceorm.sessions.database.config.SpringsPersistenceOrmSessionsDatabaseConfiguration;
import com.github.justincranford.springs.persistenceorm.sessions.json.config.SpringsPersistenceOrmSessionsCustomObjectMapperConfiguration;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmSessionsServiceConfiguration;
import com.github.justincranford.springs.persistenceorm.clients.config.SpringsPersistenceOrmClientsConfiguration;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmUsersConfiguration;
import com.github.justincranford.springs.util.https.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;

@Configuration
@Import({
	SpringsPersistenceOrmUsersConfiguration.class,
	SpringsPersistenceOrmClientsConfiguration.class,
	SpringsUtilHttpsConfiguration.class,
    SpringsUtilSecurityHashesConfiguration.class,
	SpringsPersistenceOrmSessionsDatabaseConfiguration.class,
	SpringsPersistenceOrmSessionsServiceConfiguration.class,
	SpringsPersistenceOrmSessionsCustomObjectMapperConfiguration.class
})
public class SpringsPersistenceOrmSessionsConfiguration {
	// do nothing
}
