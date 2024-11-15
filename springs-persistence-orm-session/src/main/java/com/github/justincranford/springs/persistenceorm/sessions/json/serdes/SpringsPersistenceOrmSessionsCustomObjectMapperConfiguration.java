package com.github.justincranford.springs.persistenceorm.sessions.json.serdes;

import com.fasterxml.jackson.databind.module.SimpleModule;
import com.github.justincranford.springs.persistenceorm.sessions.database.util.CustomGrantedAuthority;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

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

        existingObjectMapper.configure(DeserializationFeature.FAIL_ON_TRAILING_TOKENS, false);

        return existingObjectMapper;
    }
}
