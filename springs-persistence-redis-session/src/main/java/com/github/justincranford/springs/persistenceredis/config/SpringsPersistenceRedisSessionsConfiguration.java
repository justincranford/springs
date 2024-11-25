package com.github.justincranford.springs.persistenceredis.config;

import com.github.justincranford.springs.persistenceorm.clients.config.SpringsPersistenceOrmClientsConfiguration;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmUsersConfiguration;
import com.github.justincranford.springs.persistenceredis.properties.config.SpringsPersistenceRedisSessionsPropertiesConfiguration;
import com.github.justincranford.springs.persistenceredis.sessions.config.SpringsPersistenceRedisSessionsPersistenceConfiguration;
import com.github.justincranford.springs.util.https.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
	SpringsUtilHttpsConfiguration.class,
    SpringsUtilSecurityHashesConfiguration.class,
	SpringsPersistenceOrmUsersConfiguration.class,
	SpringsPersistenceOrmClientsConfiguration.class,
	SpringsPersistenceRedisSessionsPropertiesConfiguration.class,
	SpringsPersistenceRedisSessionsPersistenceConfiguration.class
})
public class SpringsPersistenceRedisSessionsConfiguration {
	// do nothing
}
