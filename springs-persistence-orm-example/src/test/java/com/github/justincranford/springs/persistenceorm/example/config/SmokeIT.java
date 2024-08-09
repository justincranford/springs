package com.github.justincranford.springs.persistenceorm.example.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.persistenceorm.example.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SmokeIT extends AbstractIT {
	@Test
	void contextLoads() {
		assertThat(super.meterRegistry()).isNotNull();
		assertThat(super.applicationContext()).isNotNull();
		assertThat(super.appleOrmRepository()).isNotNull();
		assertThat(super.bushelOrmRepository()).isNotNull();
	}
}
