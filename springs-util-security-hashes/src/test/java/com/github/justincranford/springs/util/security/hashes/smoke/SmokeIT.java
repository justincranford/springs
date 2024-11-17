package com.github.justincranford.springs.util.security.hashes.smoke;

import com.github.justincranford.springs.util.security.hashes.AbstractIT;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

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
