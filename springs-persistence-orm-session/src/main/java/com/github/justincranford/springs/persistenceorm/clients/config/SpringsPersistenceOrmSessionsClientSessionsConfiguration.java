package com.github.justincranford.springs.persistenceorm.clients.config;

import com.github.justincranford.springs.persistenceorm.clients.client.service.ClientService;
import com.github.justincranford.springs.persistenceorm.clients.repository.ClientSessionPojoRepository;
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
	basePackageClasses={ ClientService.class, ClientSessionPojoRepository.class}
)
public class SpringsPersistenceOrmSessionsClientSessionsConfiguration {
	// do nothing
}
