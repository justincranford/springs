package com.github.justincranford.springs.util.http.server.ratelimit.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.util.http.server.ratelimit.filter.RateLimitFilter;
import com.github.justincranford.springs.util.http.server.ratelimit.properties.SpringsUtilHttpRateLimitProperties;

@Configuration
@ComponentScan(
	basePackageClasses={RateLimitFilter.class}
)
@EnableConfigurationProperties(
	value={SpringsUtilHttpRateLimitProperties.class}
)
public class SpringsUtilHttpRateLimitConfiguration {
	// do nothing
}
