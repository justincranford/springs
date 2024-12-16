package com.github.justincranford.springs.persistenceredis.serdes.serdes;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;
import org.springframework.stereotype.Component;

@Component
@NoArgsConstructor
public class JsonRedisSerializer implements RedisSerializer<Object> {
    /** @see com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration */
    @Autowired
    @Qualifier("objectMapperPersistence")
    private ObjectMapper objectMapper;

    @Override
    public byte[] serialize(final Object value) throws SerializationException {
        try {
            return this.objectMapper.writeValueAsBytes(value);
        } catch (Exception e) {
            throw new SerializationException("Error serializing object", e);
        }
    }

    @Override
    public Object deserialize(final byte[] bytes) throws SerializationException {
        try {
            if (bytes == null || bytes.length == 0) {
                return null;
            }
            return this.objectMapper.readValue(bytes, Object.class);
        } catch (Exception e) {
            throw new SerializationException("Error deserializing object", e);
        }
    }
}
