package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={CustomUserDetailsService.class, PersonProperties.class}
)
@EnableConfigurationProperties
public class SpringsAuthenticationOrmUsersAuthenticationPropertiesConfiguration {
	// do nothing
}
