package com.github.justincranford.springs.util.http.server.logging.config;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.util.http.server.logging.filter.RequestLogFilter;

@Configuration
@ComponentScan(
	basePackageClasses={RequestLogFilter.class}
)
public class SpringsUtilHttpRequestLogConfiguration {
	// do nothing
}
