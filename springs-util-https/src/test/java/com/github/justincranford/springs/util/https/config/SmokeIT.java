package com.github.justincranford.springs.util.https.config;

import com.github.justincranford.springs.util.https.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SmokeIT extends AbstractIT {
    @Test
    void testBeans() {
        assertThat(super.serverAddress()).isNotNull();
        assertThat(super.httpRestTemplate()).isNotNull();
        assertThat(super.mtlsRestTemplate()).isNotNull();
        assertThat(super.stlsRestTemplate()).isNotNull();
        assertThat(super.ptlsRestTemplate()).isNotNull();
        assertThat(super.stlsSslContext()).isNotNull();
        assertThat(super.mtlsSslContext()).isNotNull();
        assertThat(super.ptlsSslContext()).isNotNull();
        assertThat(super.httpBaseUrl()).isNotNull();
        assertThat(super.httpsBaseUrl()).isNotNull();
    }
}
