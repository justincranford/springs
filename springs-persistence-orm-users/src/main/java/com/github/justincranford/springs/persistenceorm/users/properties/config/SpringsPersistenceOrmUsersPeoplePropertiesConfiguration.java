package com.github.justincranford.springs.persistenceorm.users.properties.config;

import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties;
import com.github.justincranford.springs.persistenceorm.users.properties.service.LoadPeoplePropertiesIntoDatabase;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={ SpringsPersistenceOrmUsersPeopleProperties.class, LoadPeoplePropertiesIntoDatabase.class}
)
@EnableConfigurationProperties
public class SpringsPersistenceOrmUsersPeoplePropertiesConfiguration {
	// do nothing
}
