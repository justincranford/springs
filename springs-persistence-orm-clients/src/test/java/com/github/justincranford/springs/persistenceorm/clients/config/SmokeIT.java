package com.github.justincranford.springs.persistenceorm.clients.config;

import com.github.justincranford.springs.persistenceorm.clients.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SmokeIT extends AbstractIT {
    @Test
    void testBeans() {
        assertThat(super.meterRegistry()).isNotNull();
        assertThat(super.applicationContext()).isNotNull();
        assertThat(super.clientOrmRepository()).isNotNull();
        assertThat(super.clientsProperties()).isNotNull();
        assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
    }
}
