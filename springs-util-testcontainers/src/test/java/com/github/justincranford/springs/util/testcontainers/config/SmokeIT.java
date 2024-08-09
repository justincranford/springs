package com.github.justincranford.springs.util.testcontainers.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.testcontainers.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SmokeIT extends AbstractIT {
	@Test
	void contextLoads() {
		assertThat(super.applicationContext()).isNotNull();
	}
}
