package com.github.justincranford.springs.authenticationorm.users.authentication.provider.config;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonaEmailPasswordAuthenticationProvider;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
    basePackageClasses = { PersonaEmailPasswordAuthenticationProvider.class, PersonUsernamePasswordAuthenticationProvider.class }
)
public class SpringsAuthenticationOrmUsersAuthenticationProvidersConfiguration {
    // do nothing
}
