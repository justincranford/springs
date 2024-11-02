package com.github.justincranford.springs.authenticationorm.users.ratelimit.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={RateLimitingFilter.class}
)
public class SpringsAuthenticationOrmUsersRateLimitConfiguration {
	// do nothing
}
