package com.github.justincranford.springs.persistenceorm.users.properties;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={SpringsPersistenceOrmUsersPeopleProperties.class, LoadPeoplePropertiesIntoDatabase.class}
)
@EnableConfigurationProperties
public class SpringsPersistenceOrmUsersPeoplePropertiesConfiguration {
	// do nothing
}
