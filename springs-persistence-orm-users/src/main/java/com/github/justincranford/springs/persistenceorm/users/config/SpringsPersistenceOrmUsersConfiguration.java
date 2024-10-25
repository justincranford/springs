package com.github.justincranford.springs.persistenceorm.users.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;

@Configuration
@EnableJpaRepositories(
	basePackageClasses = {PersonOrm.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@Import({
	SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	SpringsUtilObservabilityConfiguration.class
})
public class SpringsPersistenceOrmUsersConfiguration {
	// do nothing
}
