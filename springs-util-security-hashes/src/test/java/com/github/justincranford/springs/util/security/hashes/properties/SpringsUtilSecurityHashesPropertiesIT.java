package com.github.justincranford.springs.util.security.hashes.properties;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.security.hashes.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@SuppressWarnings("nls")
@Slf4j
public class SpringsUtilSecurityHashesPropertiesIT extends AbstractIT {
	@Test
	void loadBaseProperties() {
		assertThat(super.springsUtilSecurityHashesProperties()).isNotNull();
		log.info("properties: {}", super.springsUtilSecurityHashesProperties());
	}
}
