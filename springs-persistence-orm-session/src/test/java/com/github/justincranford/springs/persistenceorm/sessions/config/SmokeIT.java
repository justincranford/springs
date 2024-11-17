package com.github.justincranford.springs.persistenceorm.sessions.config;

import com.github.justincranford.springs.persistenceorm.sessions.AbstractIT;
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
        assertThat(super.sessionOrmRepository()).isNotNull();
        assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
        assertThat(super.springsPersistenceOrmUsersPeopleProperties()).isNotNull();
        assertThat(super.http()).isNotNull();
        assertThat(super.repository()).isNotNull();
        assertThat(super.serverAddress()).isNotNull();
        assertThat(super.webServerApplicationContext()).isNotNull();
        assertThat(super.sslBundles()).isNotNull();
        assertThat(super.httpRestTemplate()).isNotNull();
        assertThat(super.mtlsRestTemplate()).isNotNull();
        assertThat(super.stlsRestTemplate()).isNotNull();
        assertThat(super.ptlsRestTemplate()).isNotNull();
        assertThat(super.stlsSslContext()).isNotNull();
        assertThat(super.mtlsSslContext()).isNotNull();
        assertThat(super.ptlsSslContext()).isNotNull();
        assertThat(super.objectMapper()).isNotNull();
        assertThat(super.httpBaseUrl()).isNotNull();
        assertThat(super.httpsBaseUrl()).isNotNull();
    }
}
