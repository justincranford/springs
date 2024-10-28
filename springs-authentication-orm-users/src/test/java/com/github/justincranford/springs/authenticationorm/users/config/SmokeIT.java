package com.github.justincranford.springs.authenticationorm.users.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.authenticationorm.users.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SmokeIT extends AbstractIT {
	@Test
	void testBeans() {
		assertThat(super.meterRegistry()).isNotNull();
		assertThat(super.applicationContext()).isNotNull();
		assertThat(super.personOrmRepository()).isNotNull();
		assertThat(super.personaOrmRepository()).isNotNull();
		assertThat(super.sessionOrmRepository()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
	}
}
