package com.github.justincranford.springs.persistenceorm.clients.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.persistenceorm.clients.client.config.SpringsPersistenceOrmClientsClientConfiguration;
import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientPropertiesConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;

@Configuration
@Import({
	SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	SpringsUtilObservabilityConfiguration.class,
	SpringsPersistenceOrmClientsClientConfiguration.class,
	SpringsPersistenceOrmClientsClientPropertiesConfiguration.class
})
public class SpringsPersistenceOrmClientsConfiguration {
	// do nothing
}
