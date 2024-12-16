package com.github.justincranford.springs.persistenceredis.serdes.serdes;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;

@RequiredArgsConstructor
@Slf4j
public class GenericJsonDeserializer<CLAZZ> extends JsonDeserializer<CLAZZ> {
    private final ObjectMapper objectMapper;
    private final Class<CLAZZ> clazz;

    @Override
    public CLAZZ deserialize(final JsonParser jsonParser, final DeserializationContext deserializationContext) throws IOException {
        final String string = jsonParser.getValueAsString();
        log.info("{}:\n{}", this.clazz.getCanonicalName(), string);
        if (string == null || string.isEmpty()) {
            return null;
        }
        return this.objectMapper.readValue(string, this.clazz);
    }
}
