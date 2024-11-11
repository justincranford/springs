package com.github.justincranford.springs.util.security.passwords.smoke;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.security.passwords.AbstractIT;

public class SmokeIT extends AbstractIT {
	@Test
	void loadProperties() {
		assertThat(super.applicationContext()).isNotNull();
		assertThat(super.springsUtilSecurityHashesProperties()).isNotNull();
	}
}
