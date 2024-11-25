package com.github.justincranford.springs.persistenceorm.clients.client.config;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrmRepository;
import com.github.justincranford.springs.persistenceorm.clients.client.service.ClientSecretUpgradeEncodingService;
import com.github.justincranford.springs.persistenceorm.clients.client.service.ClientService;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(
	basePackageClasses={ClientOrm.class}
)
@EnableJpaRepositories(
	basePackageClasses = {ClientOrmRepository.class},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@ComponentScan(
	basePackageClasses={ClientService.class, ClientSecretUpgradeEncodingService.class}
)
public class SpringsPersistenceOrmClientsClientConfiguration {
	// do nothing
}
