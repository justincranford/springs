package com.github.justincranford.springs.util.json.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.justincranford.springs.util.json.PrettyJson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Configuration
@Import({PrettyJson.class})
@SuppressWarnings({"unused", "static-method"})
@Slf4j
public class SpringsUtilJsonConfiguration {
	@Bean
	public ObjectMapper objectMapper() {
		return new ObjectMapper()
		.registerModule(new JavaTimeModule())
		.registerModule(new Jdk8Module())
		.setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
//		.setSerializationInclusion(JsonInclude.Include.ALWAYS)
		.enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
		.configure(SerializationFeature.INDENT_OUTPUT, true)
		.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
		.configure(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS, false)
		.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
		.configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true)
		.configure(DeserializationFeature.FAIL_ON_NUMBERS_FOR_ENUMS, true)
		.configure(DeserializationFeature.FAIL_ON_READING_DUP_TREE_KEY, true)
		.configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, true)
		.configure(DeserializationFeature.FAIL_ON_MISSING_CREATOR_PROPERTIES, false)
		.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, true)
		.configure(DeserializationFeature.FAIL_ON_UNEXPECTED_VIEW_PROPERTIES, true)
		.configure(DeserializationFeature.ACCEPT_FLOAT_AS_INT, false)
		;
	}
}
