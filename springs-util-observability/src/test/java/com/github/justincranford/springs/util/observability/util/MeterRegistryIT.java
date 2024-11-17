package com.github.justincranford.springs.util.observability.util;

import com.github.justincranford.springs.util.observability.AbstractIT;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class MeterRegistryIT extends AbstractIT {
    @Test
    void testMeterRegistry() {
        assertThat(meterRegistry()).isNotNull();
    }
}
