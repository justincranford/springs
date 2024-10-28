package com.github.justincranford.springs.authenticationorm.users.session;

import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(
	basePackageClasses={SessionOrm.class}
)
@EnableJpaRepositories(
	basePackageClasses = {SessionOrmRepository.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
public class SpringsAuthenticationOrmUsersSessionConfiguration {
	// do nothing
}
