package com.github.justincranford.springs.persistenceorm.base.converter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import lombok.RequiredArgsConstructor;

@Converter
@RequiredArgsConstructor
public class JsonConverterDelegate<T> implements AttributeConverter<T, String> {
    private final ObjectMapper objectMapper;
    private final TypeReference<T> typeReference;

    @Override
    public String convertToDatabaseColumn(final T unencoded) {
        try {
            return unencoded == null ? null : this.objectMapper.writeValueAsString(unencoded);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public T convertToEntityAttribute(final String encoded) {
        try {
            return encoded == null ? null : this.objectMapper.readValue(encoded, this.typeReference);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}

