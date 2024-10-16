package com.github.justincranford.springs.persistenceorm.example.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.persistenceorm.example.apple.AppleOrm;
import com.github.justincranford.springs.persistenceorm.example.bushel.BushelOrm;
import com.github.justincranford.springs.persistenceorm.example.properties.SpringsPersistenceOrmExampleProperties;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;

@Configuration
@EnableConfigurationProperties
//@ComponentScan(
//	basePackageClasses = {SpringsPersistenceOrmExampleProperties.class}
//)
@EnableJpaRepositories(
	basePackageClasses = {AppleOrm.class, BushelOrm.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@Import({
	SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	SpringsUtilObservabilityConfiguration.class
})
public class SpringsPersistenceOrmExampleConfiguration {
	// do nothing
}
