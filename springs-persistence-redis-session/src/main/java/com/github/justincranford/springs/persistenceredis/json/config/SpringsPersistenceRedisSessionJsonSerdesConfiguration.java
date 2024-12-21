package com.github.justincranford.springs.persistenceredis.json.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.jackson2.SecurityJackson2Modules;

@Configuration
@Slf4j
@SuppressWarnings({"unused"})
public class SpringsPersistenceRedisSessionJsonSerdesConfiguration {
    /** @see  com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration#objectMapper */
    @Autowired
    private ObjectMapper objectMapper;

    @PostConstruct
    public void postConstruct() {
        updateObjectMapper(this.objectMapper);
    }

    public static void updateObjectMapper(final ObjectMapper objectMapper) {
        objectMapper. registerModules(SecurityJackson2Modules.getModules(SpringsPersistenceRedisSessionJsonSerdesConfiguration.class.getClassLoader()));
        log.info("Registered Modules:\n{}", objectMapper.getRegisteredModuleIds());
    }
}
