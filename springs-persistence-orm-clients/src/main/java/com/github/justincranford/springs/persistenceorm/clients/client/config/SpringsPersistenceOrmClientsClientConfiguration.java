package com.github.justincranford.springs.persistenceorm.clients.client.config;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrmRepository;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(
    basePackageClasses = { ClientOrm.class }
)
@EnableJpaRepositories(
    basePackageClasses = { ClientOrmRepository.class },
    repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
public class SpringsPersistenceOrmClientsClientConfiguration {
    // do nothing
}
