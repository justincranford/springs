package com.github.justincranford.springs.persistenceorm.clients.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.persistenceorm.clients.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SmokeIT extends AbstractIT {
	@Test
	void testBeans() {
		assertThat(super.meterRegistry()).isNotNull();
		assertThat(super.applicationContext()).isNotNull();
		assertThat(super.clientOrmRepository()).isNotNull();
		assertThat(super.clientsProperties()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
	}
}
