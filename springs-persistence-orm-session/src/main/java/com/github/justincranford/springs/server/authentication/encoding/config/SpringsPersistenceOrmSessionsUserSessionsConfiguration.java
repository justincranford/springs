package com.github.justincranford.springs.server.authentication.encoding.config;

import com.github.justincranford.springs.persistenceorm.users.person.service.PersonService;
import com.github.justincranford.springs.persistenceorm.users.persona.service.PersonaService;
import com.github.justincranford.springs.persistenceorm.users.repository.UserSessionPojoRepository;
import com.github.justincranford.springs.persistenceredis.sessions.database.config.SpringsPersistenceOrmSessionsDatabaseConfiguration;
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
	basePackageClasses={PersonService.class, PersonaService.class, UserSessionPojoRepository.class}
)
public class SpringsPersistenceOrmSessionsUserSessionsConfiguration {
	// do nothing
}
