package com.github.justincranford.springs.authenticationorm.users.ratelimit.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.authenticationorm.users.ratelimit.filter.RateLimitingFilter;
import com.github.justincranford.springs.authenticationorm.users.ratelimit.properties.SpringsAuthenticationOrmUsersRateLimitProperties;

@Configuration
@ComponentScan(
	basePackageClasses={RateLimitingFilter.class}
)
@EnableConfigurationProperties(
	value={SpringsAuthenticationOrmUsersRateLimitProperties.class}
)
public class SpringsAuthenticationOrmUsersRateLimitConfiguration {
	// do nothing
}
