package com.github.justincranford.springs.authenticationorm.users.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.authenticationorm.users.authentication.SpringsAuthenticationOrmUsersAuthenticationConfiguration;
import com.github.justincranford.springs.authenticationorm.users.authentication.config.SpringsAuthenticationOrmUsersAuthenticationPropertiesConfiguration;
import com.github.justincranford.springs.authenticationorm.users.session.SpringsAuthenticationOrmUsersSessionConfiguration;
import com.github.justincranford.springs.persistenceorm.users.config.SpringsPersistenceOrmUsersConfiguration;
import com.github.justincranford.springs.util.security.hashes.config.SpringsUtilSecurityHashesConfiguration;

@Configuration
@Import({
	SpringsPersistenceOrmUsersConfiguration.class,
    SpringsUtilSecurityHashesConfiguration.class,
    SpringsAuthenticationOrmUsersAuthenticationPropertiesConfiguration.class,
	SpringsAuthenticationOrmUsersAuthenticationConfiguration.class,
	SpringsAuthenticationOrmUsersSessionConfiguration.class
})
public class SpringsAuthenticationOrmUsersConfiguration {
	// do nothing
}
