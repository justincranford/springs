package com.github.justincranford.springs.server.authentication.encoding.config;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.persistenceorm.users.person.config.SpringsPersistenceOrmUsersPersonConfiguration;
import com.github.justincranford.springs.persistenceorm.users.persona.config.SpringsPersistenceOrmUsersPersonaConfiguration;
import com.github.justincranford.springs.persistenceorm.users.properties.config.SpringsPersistenceOrmUsersPeoplePropertiesConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;
import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;
import com.github.justincranford.springs.util.security.passwords.config.SpringsUtilSecurityPasswordsConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
	SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	SpringsUtilObservabilityConfiguration.class,
	SpringsUtilSecurityPasswordsConfiguration.class,
	SpringsUtilSecurityHashesConfiguration.class,
	SpringsPersistenceOrmUsersPersonConfiguration.class,
	SpringsPersistenceOrmUsersPersonaConfiguration.class,
	SpringsPersistenceOrmUsersPeoplePropertiesConfiguration.class
})
public class SpringsPersistenceOrmUsersConfiguration {
	// do nothing
}
