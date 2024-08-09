package com.github.justincranford.springs.persistenceorm.base.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.persistenceorm.base.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@SuppressWarnings("nls")
@Slf4j
public class SmokeIT extends AbstractIT {
	@Test
	void contextLoads() {
		assertThat(super.meterRegistry()).isNotNull();
		assertThat(super.applicationContext()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
		log.info("springsPersistenceOrmBaseProperties: {}", super.springsPersistenceOrmBaseProperties());
	}
}
