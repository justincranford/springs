package com.github.justincranford.springs.persistenceorm.users.properties;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={SpringsPersistenceOrmUsersProperties.class}
)
@EnableConfigurationProperties
public class SpringsPersistenceOrmUsersPropertiesConfiguration {
	// do nothing
}
