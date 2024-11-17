package com.github.justincranford.springs.util.security.passwords.properties;

import com.github.justincranford.springs.util.security.passwords.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SpringsUtilSecurityHashesPropertiesIT extends AbstractIT {
    @Test
    void loadBaseProperties() {
        assertThat(super.springsUtilSecurityHashesProperties()).isNotNull();
        log.info("properties: {}", super.springsUtilSecurityHashesProperties());
    }
}
