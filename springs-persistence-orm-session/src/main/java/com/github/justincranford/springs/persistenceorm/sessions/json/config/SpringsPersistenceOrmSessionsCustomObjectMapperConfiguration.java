package com.github.justincranford.springs.persistenceorm.sessions.json.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.github.justincranford.springs.persistenceorm.sessions.database.util.CustomGrantedAuthority;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.CustomGrantedAuthorityDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.SimpleGrantedAuthorityDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.UsernamePasswordAuthenticationTokenDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.WebAuthenticationDetailsDeserializer;

@Configuration
@SuppressWarnings({"static-method"})
public class SpringsPersistenceOrmSessionsCustomObjectMapperConfiguration {
	@Bean
    public ObjectMapper customObjectMapper(ObjectMapper existingObjectMapper) {
		existingObjectMapper.registerModule(simpleModule(WebAuthenticationDetails.class,            new WebAuthenticationDetailsDeserializer()));
		existingObjectMapper.registerModule(simpleModule(CustomGrantedAuthority.class,              new CustomGrantedAuthorityDeserializer()));
		existingObjectMapper.registerModule(simpleModule(SimpleGrantedAuthority.class,              new SimpleGrantedAuthorityDeserializer()));
		existingObjectMapper.registerModule(simpleModule(UsernamePasswordAuthenticationToken.class, new UsernamePasswordAuthenticationTokenDeserializer()));
        existingObjectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);
        return existingObjectMapper;
    }

	private <TYPE> SimpleModule simpleModule(final Class<TYPE> type, final JsonDeserializer<TYPE> des) {
		final SimpleModule module = new SimpleModule();
		module.addDeserializer(type, des);
        return module;
	}
}
