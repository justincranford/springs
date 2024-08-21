package com.github.justincranford.springs.util.security.hashes.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.security.hashes.AbstractIT;

public class SmokeIT extends AbstractIT {
	@Test
	void loadProperties() {
		assertThat(super.applicationContext()).isNotNull();
	}
}
