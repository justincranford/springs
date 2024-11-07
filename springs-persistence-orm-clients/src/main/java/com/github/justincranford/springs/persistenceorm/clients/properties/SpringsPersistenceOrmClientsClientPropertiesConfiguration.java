package com.github.justincranford.springs.persistenceorm.clients.properties;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={SpringsPersistenceOrmClientsClientProperties.class, LoadClientsPropertiesIntoDatabase.class}
)
@EnableConfigurationProperties
public class SpringsPersistenceOrmClientsClientPropertiesConfiguration {
	// do nothing
}
