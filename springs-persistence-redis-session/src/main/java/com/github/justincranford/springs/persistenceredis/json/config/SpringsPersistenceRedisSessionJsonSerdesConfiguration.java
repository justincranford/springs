package com.github.justincranford.springs.persistenceredis.json.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;

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
//        final List<Module> modules = SecurityJackson2Modules.getModules(SpringsPersistenceRedisSessionJsonSerdesConfiguration.class.getClassLoader());
//        log.info("Available Modules:\n{}", modules);
//        objectMapper.registerModules(modules);
//        log.info("Registered Modules:\n{}", objectMapper.getRegisteredModuleIds());
    }
}
