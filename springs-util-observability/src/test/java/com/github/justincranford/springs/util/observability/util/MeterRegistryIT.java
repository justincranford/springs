package com.github.justincranford.springs.util.observability.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.util.observability.AbstractIT;

public class MeterRegistryIT extends AbstractIT {
	@Test
	void testMeterRegistry() {
		assertThat(meterRegistry()).isNotNull();
	}
}
