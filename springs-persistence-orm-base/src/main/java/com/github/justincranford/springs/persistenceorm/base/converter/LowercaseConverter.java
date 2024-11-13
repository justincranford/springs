package com.github.justincranford.springs.persistenceorm.base.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
public class LowercaseConverter implements AttributeConverter<String, String> {
    @Override
    public String convertToDatabaseColumn(final String attribute) {
        return attribute == null ? null : attribute.toLowerCase();
    }
    @Override
    public String convertToEntityAttribute(final String dbData) {
        return dbData;
    }
}