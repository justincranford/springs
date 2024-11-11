package com.github.justincranford.springs.util.security.passwords.smoke;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.security.passwords.AbstractIT;

public class SmokeIT extends AbstractIT {
	@Test
	void loadProperties() {
		assertThat(super.applicationContext()).isNotNull();
		assertThat(super.springsUtilSecurityHashesProperties()).isNotNull();
		assertThat(super.usersPasswordGenerator()).isNotNull();
		assertThat(super.clientsPasswordGenerator()).isNotNull();
		assertThat(super.serversPasswordGenerator()).isNotNull();
		assertThat(super.defaultsPasswordGenerator()).isNotNull();
		assertThat(super.usersPasswordValidator()).isNotNull();
		assertThat(super.clientsPasswordValidator()).isNotNull();
		assertThat(super.serversPasswordValidator()).isNotNull();
		assertThat(super.defaultsPasswordValidator()).isNotNull();
	}
}
