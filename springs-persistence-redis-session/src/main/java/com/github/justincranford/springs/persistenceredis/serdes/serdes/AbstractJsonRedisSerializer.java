package com.github.justincranford.springs.persistenceredis.serdes.serdes;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.data.redis.serializer.SerializationException;

@RequiredArgsConstructor
public abstract class AbstractJsonRedisSerializer<T> implements RedisSerializer<T> {
    private final ObjectMapper objectMapper;
    private final Class<T> clazz;

    @Override
    public byte[] serialize(final T value) throws SerializationException {
        try {
            return this.objectMapper.writeValueAsBytes(value);
        } catch (Exception e) {
            throw new SerializationException("Error serializing object of type: " + this.clazz.getName(), e);
        }
    }

    @Override
    public T deserialize(final byte[] bytes) throws SerializationException {
        try {
            if (bytes == null || bytes.length == 0) {
                return null;
            }
            return this.objectMapper.readValue(bytes, this.clazz);
        } catch (Exception e) {
            throw new SerializationException("Error deserializing object of type: " + this.clazz.getName(), e);
        }
    }
}
