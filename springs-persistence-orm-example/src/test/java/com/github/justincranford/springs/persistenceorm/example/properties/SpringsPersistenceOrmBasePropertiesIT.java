package com.github.justincranford.springs.persistenceorm.example.properties;

import com.github.justincranford.springs.persistenceorm.example.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class SpringsPersistenceOrmBasePropertiesIT extends AbstractIT {
    @Test
    void loadExampleProperties() {
        assertThat(super.springsPersistenceOrmExampleProperties()).isNotNull();
        log.info("{}", super.springsPersistenceOrmExampleProperties());
    }

    @Test
    void loadBaseProperties() {
        assertThat(super.springsPersistenceOrmBaseProperties()).isNotNull();
        log.info("{}", super.springsPersistenceOrmBaseProperties());
    }
}
