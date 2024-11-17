package com.github.justincranford.springs.authenticationorm.users.config;

import com.github.justincranford.springs.authenticationorm.users.authentication.config.SpringsAuthenticationOrmUsersSecurityFilterChainConfiguration;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.config.SpringsAuthenticationOrmUsersAuthenticationProvidersConfiguration;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.config.SpringsAuthenticationOrmUsersAuthenticationUserDetailsConfiguration;
import com.github.justincranford.springs.persistenceorm.sessions.config.SpringsPersistenceOrmSessionsConfiguration;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmUsersConfiguration;
import com.github.justincranford.springs.util.https.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({
    SpringsPersistenceOrmUsersConfiguration.class,
    SpringsPersistenceOrmSessionsConfiguration.class,
    SpringsUtilHttpsConfiguration.class,
    SpringsUtilSecurityHashesConfiguration.class,
    SpringsAuthenticationOrmUsersAuthenticationProvidersConfiguration.class,
    SpringsAuthenticationOrmUsersAuthenticationUserDetailsConfiguration.class,
    SpringsAuthenticationOrmUsersSecurityFilterChainConfiguration.class
})
public class SpringsAuthenticationOrmUsersConfiguration {
    // do nothing
}
