package com.github.justincranford.springs.persistenceredis.properties.config;

import com.github.justincranford.springs.persistenceredis.properties.RedisProperties;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(
	basePackageClasses={RedisProperties.class}
)
@EnableConfigurationProperties
@Slf4j
public class SpringsPersistenceRedisSessionsPropertiesConfiguration {
	// empty
}
