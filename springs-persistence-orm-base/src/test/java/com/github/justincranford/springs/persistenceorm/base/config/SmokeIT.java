package com.github.justincranford.springs.persistenceorm.base.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.persistenceorm.base.AbstractIT;

public class SmokeIT extends AbstractIT {
	@Test
	void loadProperties() {
		assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
	}
}
