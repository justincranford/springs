package com.github.justincranford.springs.util.http.server.logging.config;

import com.github.justincranford.springs.util.http.server.logging.filter.RequestLogFilter;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
    basePackageClasses = { RequestLogFilter.class }
)
public class SpringsUtilHttpRequestLogConfiguration {
    // do nothing
}
