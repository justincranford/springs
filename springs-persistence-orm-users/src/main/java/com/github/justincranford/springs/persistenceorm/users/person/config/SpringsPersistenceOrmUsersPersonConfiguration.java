package com.github.justincranford.springs.persistenceorm.users.person.config;

import com.github.justincranford.springs.persistenceorm.users.person.service.PersonPasswordUpgradeEncodingService;
import com.github.justincranford.springs.persistenceorm.users.person.service.PersonService;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;

@Configuration
@EntityScan(
	basePackageClasses={PersonOrm.class}
)
@EnableJpaRepositories(
	basePackageClasses = {PersonOrmRepository.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@ComponentScan(
	basePackageClasses={PersonService.class, PersonPasswordUpgradeEncodingService.class}
)
public class SpringsPersistenceOrmUsersPersonConfiguration {
	// do nothing
}
