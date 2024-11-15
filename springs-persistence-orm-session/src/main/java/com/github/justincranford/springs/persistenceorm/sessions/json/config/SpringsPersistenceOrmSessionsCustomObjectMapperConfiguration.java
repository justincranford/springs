package com.github.justincranford.springs.persistenceorm.sessions.json.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.github.justincranford.springs.persistenceorm.sessions.database.util.CustomGrantedAuthority;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.CustomGrantedAuthorityDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.UsernamePasswordAuthenticationTokenDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.json.serdes.WebAuthenticationDetailsDeserializer;

@Configuration
@SuppressWarnings({"static-method"})
public class SpringsPersistenceOrmSessionsCustomObjectMapperConfiguration {
	@Bean
    public ObjectMapper customObjectMapper(ObjectMapper existingObjectMapper) {
        final SimpleModule module1 = new SimpleModule();
        module1.addDeserializer(WebAuthenticationDetails.class, new WebAuthenticationDetailsDeserializer());
        existingObjectMapper.registerModule(module1);

        final SimpleModule module2 = new SimpleModule();
        module2.addDeserializer(CustomGrantedAuthority.class, new CustomGrantedAuthorityDeserializer());
        existingObjectMapper.registerModule(module2);

        final SimpleModule module3 = new SimpleModule();
        module3.addDeserializer(UsernamePasswordAuthenticationToken.class, new UsernamePasswordAuthenticationTokenDeserializer());
        existingObjectMapper.registerModule(module3);

        existingObjectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);

        return existingObjectMapper;
    }
}
