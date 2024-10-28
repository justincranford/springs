package com.github.justincranford.springs.persistenceorm.users.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.persistenceorm.users.person.config.SpringsPersistenceOrmUsersPersonConfiguration;
import com.github.justincranford.springs.persistenceorm.users.persona.config.SpringsPersistenceOrmUsersPersonaConfiguration;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPropertiesConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;

@Configuration
@Import({
	SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	SpringsUtilObservabilityConfiguration.class,
	SpringsPersistenceOrmUsersPersonConfiguration.class,
	SpringsPersistenceOrmUsersPersonaConfiguration.class,
	SpringsPersistenceOrmUsersPropertiesConfiguration.class
})
public class SpringsPersistenceOrmUsersConfiguration {
	// do nothing
}
