package com.github.justincranford.springs.persistenceredis.serdes.serdes;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class GenericJsonSerializer<CLAZZ> extends JsonSerializer<CLAZZ> {
    private final ObjectMapper objectMapper;
    private final Class<CLAZZ> clazz;

    @Override
    public void serialize(final CLAZZ value, final JsonGenerator jsonGenerator, final SerializerProvider serializerProvider) throws IOException {
        try {
            final String string = this.objectMapper.writeValueAsString(value);
            log.info("{}:\n{}", this.clazz.getCanonicalName(), string);
            jsonGenerator.writeString(string);
        } catch (Exception e) {
            throw new RuntimeException("Error serializing object", e);
        }
    }
}
