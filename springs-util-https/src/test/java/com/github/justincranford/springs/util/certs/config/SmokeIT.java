package com.github.justincranford.springs.util.certs.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.certs.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class SmokeIT extends AbstractIT {
	@Test
	void testBeans() {
		assertThat(super.serverAddress()).isNotNull();
		assertThat(super.httpRestTemplate()).isNotNull();
		assertThat(super.mtlsRestTemplate()).isNotNull();
		assertThat(super.stlsRestTemplate()).isNotNull();
		assertThat(super.ptlsRestTemplate()).isNotNull();
		assertThat(super.httpBaseUrl()).isNotNull();
		assertThat(super.httpsBaseUrl()).isNotNull();
	}
}
