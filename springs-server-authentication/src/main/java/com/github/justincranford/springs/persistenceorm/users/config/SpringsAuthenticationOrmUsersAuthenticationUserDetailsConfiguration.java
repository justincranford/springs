package com.github.justincranford.springs.persistenceorm.users.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.persistenceorm.users.person.service.PersonPasswordUpgradeEncodingService;

@Configuration
@ComponentScan(
	basePackageClasses={ PersonPasswordUpgradeEncodingService.class}
)
public class SpringsAuthenticationOrmUsersAuthenticationUserDetailsConfiguration {
	// do nothing
}
