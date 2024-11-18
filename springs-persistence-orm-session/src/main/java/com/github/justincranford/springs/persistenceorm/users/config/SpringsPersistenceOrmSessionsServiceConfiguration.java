package com.github.justincranford.springs.persistenceorm.users.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.session.config.annotation.web.http.EnableSpringHttpSession;

import com.github.justincranford.springs.persistenceorm.sessions.database.config.SpringsPersistenceOrmSessionsDatabaseConfiguration;
import com.github.justincranford.springs.persistenceorm.users.person.service.PersonService;
import com.github.justincranford.springs.persistenceorm.users.persona.service.PersonaService;
import com.github.justincranford.springs.persistenceorm.users.repository.SessionPojoRepository;

@Configuration
@EnableSpringHttpSession
@Import({
	SpringsPersistenceOrmSessionsDatabaseConfiguration.class
})
@ComponentScan(
	basePackageClasses={PersonService.class, PersonaService.class, SessionPojoRepository.class}
)
public class SpringsPersistenceOrmSessionsServiceConfiguration {
	// do nothing
}
