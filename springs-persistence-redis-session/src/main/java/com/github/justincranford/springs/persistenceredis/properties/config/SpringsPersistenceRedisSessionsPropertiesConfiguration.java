package com.github.justincranford.springs.persistenceredis.properties.config;

import com.github.justincranford.springs.persistenceredis.properties.RedisProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={RedisProperties.class}
)
@EnableConfigurationProperties
public class SpringsPersistenceRedisSessionsPropertiesConfiguration {
	// do nothing
}
