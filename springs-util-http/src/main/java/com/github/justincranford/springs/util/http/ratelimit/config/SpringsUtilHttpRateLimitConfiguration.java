package com.github.justincranford.springs.util.http.ratelimit.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.util.http.ratelimit.filter.RateLimitFilter;
import com.github.justincranford.springs.util.http.ratelimit.properties.SpringsUtilHttpRateLimitProperties;

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
