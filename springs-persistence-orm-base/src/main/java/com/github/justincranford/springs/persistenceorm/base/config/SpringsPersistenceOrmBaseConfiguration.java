package com.github.justincranford.springs.persistenceorm.base.config;

import java.time.OffsetDateTime;
import java.util.Optional;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.auditing.DateTimeProvider;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.base.properties.SpringsPersistenceOrmBaseProperties;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;

@Configuration
@EnableConfigurationProperties
@ComponentScan(
	basePackageClasses = {SpringsPersistenceOrmBaseProperties.class}
)
@EnableJpaRepositories(
	basePackageClasses = {AbstractEntity.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@Import({
	SpringsPersistenceOrmBaseJpaAuditingConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	SpringsUtilObservabilityConfiguration.class
})
public class SpringsPersistenceOrmBaseConfiguration {
	// do nothing
}
