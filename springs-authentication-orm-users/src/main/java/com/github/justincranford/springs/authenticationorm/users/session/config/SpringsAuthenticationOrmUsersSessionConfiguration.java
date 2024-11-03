package com.github.justincranford.springs.authenticationorm.users.session.config;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.authenticationorm.users.session.SessionOrm;
import com.github.justincranford.springs.authenticationorm.users.session.SessionOrmRepository;
import com.github.justincranford.springs.authenticationorm.users.session.SessionPojoRepository;

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
public class SpringsAuthenticationOrmUsersSessionConfiguration {
	// do nothing
}
