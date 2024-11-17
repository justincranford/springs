package com.github.justincranford.springs.util.testcontainers.config;

import com.github.justincranford.springs.util.testcontainers.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SmokeIT extends AbstractIT {
    @Test
    void contextLoads() {
        assertThat(super.applicationContext()).isNotNull();
    }
}
