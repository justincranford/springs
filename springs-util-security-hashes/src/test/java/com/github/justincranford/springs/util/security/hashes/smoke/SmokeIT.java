package com.github.justincranford.springs.util.security.hashes.smoke;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.security.hashes.AbstractIT;

public class SmokeIT extends AbstractIT {
	@Test
	void loadProperties() {
		assertThat(super.applicationContext()).isNotNull();
		assertThat(super.encodersConfiguration()).isNotNull();
		assertThat(super.passwordEncoder()).isNotNull();
		assertThat(super.keyEncoders()).isNotNull();
		assertThat(super.valueEncoders()).isNotNull();
	}
}
