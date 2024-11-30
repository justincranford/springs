package com.github.justincranford.springs.util.json.util;

import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.module.SimpleModule;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@SuppressWarnings({"unused"})
public final class ObjectMapperModuleUtil {
	public static <TYPE> SimpleModule serializer(final Class<TYPE> type, final JsonSerializer<TYPE> des) {
		final SimpleModule module = new SimpleModule();
		module.addSerializer(type, des);
		return module;
	}

	public static <TYPE> SimpleModule deserializer(final Class<TYPE> type, final JsonDeserializer<TYPE> des) {
		final SimpleModule module = new SimpleModule();
		module.addDeserializer(type, des);
		return module;
	}
}
