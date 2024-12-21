package com.github.justincranford.springs.persistenceredis.config;

import com.github.justincranford.springs.persistenceorm.clients.config.SpringsPersistenceOrmClientsConfiguration;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmUsersConfiguration;
import com.github.justincranford.springs.persistenceredis.json.config.SpringsPersistenceRedisSessionJsonSerdesConfiguration;
import com.github.justincranford.springs.persistenceredis.sessions.config.SpringsPersistenceRedisSessionsClientServerConfiguration;
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
	SpringsPersistenceRedisSessionsClientServerConfiguration.class,
	SpringsPersistenceRedisSessionJsonSerdesConfiguration.class
})
public class SpringsPersistenceRedisSessionsConfiguration {
	// do nothing
}
