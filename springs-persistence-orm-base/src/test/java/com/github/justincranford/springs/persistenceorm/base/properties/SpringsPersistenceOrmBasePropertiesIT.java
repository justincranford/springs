package com.github.justincranford.springs.persistenceorm.base.properties;

import com.github.justincranford.springs.persistenceorm.base.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SpringsPersistenceOrmBasePropertiesIT extends AbstractIT {
    @Test
    void loadBaseProperties() {
        assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
        log.info("{}", super.springsPersistenceOrmBaseProperties());
    }
}
