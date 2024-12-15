package com.github.justincranford.springs.persistenceredis.serdes.serdes;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component
public final class JsonRedisSerializer extends AbstractJsonRedisSerializer<Object> {
    public JsonRedisSerializer(
        @Qualifier("objectMapperPersistence") final ObjectMapper objectMapperPersistence
    ) {
        super(objectMapperPersistence, Object.class);
    }
}
