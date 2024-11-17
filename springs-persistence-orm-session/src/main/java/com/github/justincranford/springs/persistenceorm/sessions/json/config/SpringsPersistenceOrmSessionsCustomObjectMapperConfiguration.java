package com.github.justincranford.springs.persistenceorm.sessions.json.config;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.SimpleGrantedAuthorityDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.UsernamePasswordAuthenticationTokenDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.WebAuthenticationDetailsDeserializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import static com.github.justincranford.springs.persistenceorm.sessions.json.util.ObjectMapperModuleUtil.deserializer;

@Configuration
@SuppressWarnings({ "unused", "static-method" })
public class SpringsPersistenceOrmSessionsCustomObjectMapperConfiguration {
    @Bean
    public ObjectMapper customObjectMapper(ObjectMapper existingObjectMapper) {
        existingObjectMapper.registerModule(deserializer(WebAuthenticationDetails.class, new WebAuthenticationDetailsDeserializer()));
        existingObjectMapper.registerModule(deserializer(SimpleGrantedAuthority.class, new SimpleGrantedAuthorityDeserializer()));
        existingObjectMapper.registerModule(deserializer(UsernamePasswordAuthenticationToken.class, new UsernamePasswordAuthenticationTokenDeserializer()));
        existingObjectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);
        return existingObjectMapper;
    }
}
