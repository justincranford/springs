package com.github.justincranford.springs.util.json.config;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.cfg.MapperConfig;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.impl.LaissezFaireSubTypeValidator;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.justincranford.springs.util.json.PrettyJson;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import static com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator.Validity.ALLOWED;

@Configuration
@Import({PrettyJson.class})
@SuppressWarnings({"unused", "static-method"})
@Slf4j
public class SpringsUtilJsonConfiguration {
	@Primary
	@Bean
	@Qualifier("objectMapperTransit")
	public ObjectMapper objectMapperTransit() {
		return objectMapper(); // Exclude polymorphic type
	}

	@Bean
	@Qualifier("objectMapperPersistence")
	public ObjectMapper objectMapperPersistence() {
		return new ObjectMapper()
			.registerModule(new JavaTimeModule())
			.registerModule(new Jdk8Module())
			.setSerializationInclusion(JsonInclude.Include.NON_EMPTY) // WebAuthn RegistrationRequest.allowCredentials=null breaks JavaScript
			.enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
			.configure(SerializationFeature.INDENT_OUTPUT, true)
			.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
			.configure(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS, false)
			.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
			.activateDefaultTyping(LaissezFaireSubTypeValidator.instance, ObjectMapper.DefaultTyping.EVERYTHING, JsonTypeInfo.As.PROPERTY);
	}

	private static final PolymorphicTypeValidator SERDES_PACKAGES_ALLOW_LIST = new PolymorphicTypeValidator.Base() {
		public Validity validateSubClassName(final MapperConfig<?> mapperConfig, final String baseType, final String subType) {
			return ALLOWED;
//			if ((baseType.startsWith("com.github.justincranford.springs")) || (baseType.startsWith("org.springframework"))) {
//				log.info("Allowed JSON serialization for baseType: {}, subType: {}, mapperConfig: {}", baseType, subType, mapperConfig);
//				return ALLOWED;
//			}
//			log.info("Denied JSON serialization for baseType: {}, subType: {}, mapperConfig: {}", baseType, subType, mapperConfig);
//			return DENIED;
		}
	};

	public static ObjectMapper objectMapper() {
		return new ObjectMapper()
		.enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
//		.addMixIn(AbstractEntity.class, AbstractEntityMixin.class) // public abstract class AbstractEntityMixin { @JsonProperty("id") String id; }
//		.setSerializationInclusion(JsonInclude.Include.ALWAYS)
		.setSerializationInclusion(JsonInclude.Include.NON_EMPTY) // WebAuthn RegistrationRequest.allowCredentials=null breaks JavaScript
//		.configure(SerializationFeature.WRAP_ROOT_VALUE, true) // true breaks WebAuthn
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
//		.configure(DeserializationFeature.UNWRAP_ROOT_VALUE, true) // true breaks WebAuthn
		.configure(DeserializationFeature.ACCEPT_FLOAT_AS_INT, false)
//		.registerModule(new GeoModule())
//		.registerModule(new JsonMixinModule())
//		.registerModule(new JsonComponentModule())
//		.registerModule(new ParameterNamesModule(JsonCreator.Mode.PROPERTIES))
		.registerModule(new JavaTimeModule())
		.registerModule(new Jdk8Module())
		;
	}
}
