package com.github.justincranford.springs.persistenceorm.example.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

import com.github.justincranford.springs.util.basic.config.SpringsUtilBasicConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;
import com.github.justincranford.springs.util.observability.config.SpringsUtilObservabilityConfiguration;

@Configuration
@EnableConfigurationProperties
@ComponentScan(basePackages={"com.github.justincranford.springs.persistenceorm.example"})
@EnableJpaRepositories(basePackages={"com.github.justincranford.springs.persistenceorm.example"}, repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class)
@Import({SpringsUtilBasicConfiguration.class,SpringsUtilJsonConfiguration.class,SpringsUtilObservabilityConfiguration.class})
public class SpringsPersistenceOrmExampleConfiguration {
	// do nothing
}
