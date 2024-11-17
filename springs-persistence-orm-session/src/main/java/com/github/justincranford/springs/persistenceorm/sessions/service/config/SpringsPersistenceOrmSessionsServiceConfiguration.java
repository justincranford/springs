package com.github.justincranford.springs.persistenceorm.sessions.service.config;

import com.github.justincranford.springs.persistenceorm.sessions.database.config.SpringsPersistenceOrmSessionsDatabaseConfiguration;
import com.github.justincranford.springs.persistenceorm.sessions.service.PersonService;
import com.github.justincranford.springs.persistenceorm.sessions.service.PersonaService;
import com.github.justincranford.springs.persistenceorm.sessions.service.repository.SessionPojoRepository;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

@Configuration
@EnableSpringHttpSession
@Import({
    SpringsPersistenceOrmSessionsDatabaseConfiguration.class
})
@ComponentScan(
    basePackageClasses = { PersonService.class, PersonaService.class, SessionPojoRepository.class }
)
public class SpringsPersistenceOrmSessionsServiceConfiguration {
    // do nothing
}
