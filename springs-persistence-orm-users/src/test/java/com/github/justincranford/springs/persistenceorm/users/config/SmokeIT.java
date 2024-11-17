package com.github.justincranford.springs.persistenceorm.users.config;

import com.github.justincranford.springs.persistenceorm.users.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SmokeIT extends AbstractIT {
    @Test
    void testBeans() {
        assertThat(super.meterRegistry()).isNotNull();
        assertThat(super.applicationContext()).isNotNull();
        assertThat(super.personOrmRepository()).isNotNull();
        assertThat(super.personaOrmRepository()).isNotNull();
        assertThat(super.peopleProperties()).isNotNull();
        assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
    }
}
