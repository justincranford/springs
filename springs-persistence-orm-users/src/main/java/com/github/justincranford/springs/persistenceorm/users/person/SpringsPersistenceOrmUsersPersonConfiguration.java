package com.github.justincranford.springs.persistenceorm.users.person;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(
	basePackageClasses={PersonOrm.class, PersonaOrm.class}
)
@EnableJpaRepositories(
	basePackageClasses = {PersonOrmRepository.class,PersonaOrmRepository.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
public class SpringsPersistenceOrmUsersPersonConfiguration {
	// do nothing
}
