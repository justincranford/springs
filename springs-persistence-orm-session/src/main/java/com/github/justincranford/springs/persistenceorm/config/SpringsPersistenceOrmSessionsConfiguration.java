package com.github.justincranford.springs.persistenceorm.config;

import com.github.justincranford.springs.persistenceredis.sessions.config.SpringsPersistenceOrmSessionsSessionsConfiguration;
import com.github.justincranford.springs.persistenceredis.sessions.database.config.SpringsPersistenceOrmSessionsDatabaseConfiguration;
import com.github.justincranford.springs.persistenceredis.sessions.json.config.SpringsPersistenceOrmSessionsCustomObjectMapperConfiguration;
import com.github.justincranford.springs.util.https.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
	SpringsUtilHttpsConfiguration.class,
    SpringsUtilSecurityHashesConfiguration.class,
	SpringsPersistenceOrmSessionsDatabaseConfiguration.class,
	SpringsPersistenceOrmSessionsCustomObjectMapperConfiguration.class,
	SpringsPersistenceOrmSessionsSessionsConfiguration.class
})
public class SpringsPersistenceOrmSessionsConfiguration {
	// do nothing
}
