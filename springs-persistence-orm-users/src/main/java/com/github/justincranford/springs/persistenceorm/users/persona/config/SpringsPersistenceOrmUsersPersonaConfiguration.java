package com.github.justincranford.springs.persistenceorm.users.persona.config;

import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EntityScan(
    basePackageClasses = { PersonaOrm.class }
)
@EnableJpaRepositories(
    basePackageClasses = { PersonaOrmRepository.class },
    repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
public class SpringsPersistenceOrmUsersPersonaConfiguration {
    // do nothing
}
