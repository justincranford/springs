package com.github.justincranford.springs.persistenceorm.sessions.database.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.persistenceorm.sessions.database.entity.SessionOrm;
import com.github.justincranford.springs.persistenceorm.sessions.database.repository.SessionOrmRepository;
import com.github.justincranford.springs.persistenceorm.sessions.service.repository.SessionPojoRepository;

@Configuration
@EntityScan(
	basePackageClasses={SessionOrm.class}
)
@EnableJpaRepositories(
	basePackageClasses = {SessionOrmRepository.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@ComponentScan(
	basePackageClasses={SessionPojoRepository.class}
)
public class SpringsPersistenceOrmSessionsDatabaseConfiguration {
	// do nothing
}
