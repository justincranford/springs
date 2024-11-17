package com.github.justincranford.springs.util.http.server.ratelimit.config;

import com.github.justincranford.springs.util.http.server.ratelimit.filter.RateLimitFilter;
import com.github.justincranford.springs.util.http.server.ratelimit.properties.SpringsUtilHttpRateLimitProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
    basePackageClasses = { RateLimitFilter.class }
)
@EnableConfigurationProperties(
    value = { SpringsUtilHttpRateLimitProperties.class }
)
public class SpringsUtilHttpRateLimitConfiguration {
    // do nothing
}
