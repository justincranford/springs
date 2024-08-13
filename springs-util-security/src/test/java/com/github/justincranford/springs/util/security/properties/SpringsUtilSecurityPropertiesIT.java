package com.github.justincranford.springs.util.security.properties;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.security.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@SuppressWarnings("nls")
@Slf4j
public class SpringsUtilSecurityPropertiesIT extends AbstractIT {
	@Test
	void loadBaseProperties() {
		assertThat(super.springsUtilSecurityProperties()).isNotNull();
		log.info("properties: {}", super.springsUtilSecurityProperties());
	}
}
