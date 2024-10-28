package com.github.justincranford.springs.persistenceorm.base.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.persistenceorm.base.AbstractIT;

public class SmokeIT extends AbstractIT {
	@Test
	void loadProperties() {
		assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties().getHostName()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties().getPort()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties().getFrom()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties().getDurationInDays()).isNotNull();
		assertThat(super.springsPersistenceOrmBaseProperties().getSizeInTB()).isNotNull();
	}
}
