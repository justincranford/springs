package com.github.justincranford.springs.persistenceorm.example.config;

import com.github.justincranford.springs.persistenceorm.example.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SmokeIT extends AbstractIT {
    @Test
    void testBeans() {
        assertThat(super.meterRegistry()).isNotNull();
        assertThat(super.applicationContext()).isNotNull();
        assertThat(super.appleOrmRepository()).isNotNull();
        assertThat(super.bushelOrmRepository()).isNotNull();
        assertThat(super.springsPersistenceOrmExampleProperties()).isNotNull();
        assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
    }
}
