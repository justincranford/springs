package com.github.justincranford.springs.persistenceredis.serdes.config;

import com.github.justincranford.springs.persistenceredis.serdes.serdes.JsonRedisSerializer;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

@Configuration
@ComponentScan(basePackageClasses = {
	JsonRedisSerializer.class
})
public class SpringsPersistenceRedisSessionsSerdesConfiguration {
	// do nothing
}
