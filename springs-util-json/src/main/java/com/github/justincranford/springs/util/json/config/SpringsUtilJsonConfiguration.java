package com.github.justincranford.springs.util.json.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

@Configuration
@Import({PrettyJson.class})
@SuppressWarnings({"static-method"})
public class SpringsUtilJsonConfiguration {
	@Bean
	@Primary
	public ObjectMapper objectMapper(/* final Jackson2ObjectMapperBuilder builder */) {
		return new ObjectMapper()
			.enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
//			.addMixIn(AbstractEntity.class, AbstractEntityMixin.class) // public abstract class AbstractEntityMixin { @JsonProperty("id") String internalId; }
//			.setSerializationInclusion(JsonInclude.Include.ALWAYS)
			.setSerializationInclusion(JsonInclude.Include.NON_EMPTY) // WebAuthn RegistrationRequest.allowCredentials=null breaks JavaScript 
//			.configure(SerializationFeature.WRAP_ROOT_VALUE, true) // true breaks WebAuthn
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
//			.configure(DeserializationFeature.UNWRAP_ROOT_VALUE, true) // true breaks WebAuthn
			.configure(DeserializationFeature.ACCEPT_FLOAT_AS_INT, false)
//			.registerModule(new GeoModule())
//			.registerModule(new JsonMixinModule())
//			.registerModule(new JsonComponentModule())
//			.registerModule(new ParameterNamesModule(JsonCreator.Mode.PROPERTIES))
			.registerModule(new JavaTimeModule()).registerModule(new Jdk8Module());
	}
}
