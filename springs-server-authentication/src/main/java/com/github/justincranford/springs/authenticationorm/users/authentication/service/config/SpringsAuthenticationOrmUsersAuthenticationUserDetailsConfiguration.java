package com.github.justincranford.springs.authenticationorm.users.authentication.service.config;

import com.github.justincranford.springs.authenticationorm.users.authentication.service.PasswordUpgradeEncodingService;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
    basePackageClasses = { PasswordUpgradeEncodingService.class }
)
public class SpringsAuthenticationOrmUsersAuthenticationUserDetailsConfiguration {
    // do nothing
}
