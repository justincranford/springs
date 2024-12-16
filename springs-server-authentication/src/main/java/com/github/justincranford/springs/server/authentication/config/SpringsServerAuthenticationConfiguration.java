package com.github.justincranford.springs.server.authentication.config;

import com.github.justincranford.springs.persistenceorm.clients.config.SpringsPersistenceOrmClientsConfiguration;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmUsersConfiguration;
import com.github.justincranford.springs.persistenceredis.config.SpringsPersistenceRedisSessionsConfiguration;
import com.github.justincranford.springs.server.authentication.client.config.SpringsServerAuthenticationClientConfiguration;
import com.github.justincranford.springs.server.authentication.event.config.SpringsServerAuthenticationEventsConfiguration;
import com.github.justincranford.springs.server.authentication.filterchain.config.SpringsServerAuthenticationSecurityFilterChainConfiguration;
import com.github.justincranford.springs.server.authentication.user.config.SpringsServerAuthenticationUserConfiguration;
import com.github.justincranford.springs.server.authentication.webauthn.config.SpringsServerAuthenticationWebauthnConfiguration;
import com.github.justincranford.springs.util.https.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
	SpringsPersistenceOrmUsersConfiguration.class,
	SpringsPersistenceOrmClientsConfiguration.class,
//	SpringsPersistenceOrmSessionsConfiguration.class,	// HTTP Session storage in H2/PostgreSQL
	SpringsPersistenceRedisSessionsConfiguration.class, // HTTP Session storage in Redis
	SpringsUtilHttpsConfiguration.class,
    SpringsUtilSecurityHashesConfiguration.class,
	SpringsServerAuthenticationUserConfiguration.class,
	SpringsServerAuthenticationClientConfiguration.class,
	SpringsServerAuthenticationSecurityFilterChainConfiguration.class,
	SpringsServerAuthenticationEventsConfiguration.class,
	SpringsServerAuthenticationWebauthnConfiguration.class
})
public class SpringsServerAuthenticationConfiguration {
	// do nothing
}
