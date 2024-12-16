package com.github.justincranford.springs.server.authentication.webauthn.config;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.impl.StdTypeResolverBuilder;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.github.justincranford.springs.persistenceredis.sessions.config.SpringsPersistenceRedisSessionsClientServerConfiguration;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.BytesDeserializer;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.BytesSerializer;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnBytesMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnPublicKeyCredentialCreationOptionsMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnPublicKeyCredentialRequestOptionsMixIn;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;

@Configuration
@Slf4j
public class SpringsServerAuthenticationWebauthnConfiguration {
    /** @see SpringsPersistenceRedisSessionsClientServerConfiguration#objectMapperRedis */
    @Autowired
    @Qualifier("objectMapperRedis")
    private ObjectMapper objectMapperRedis;

    @PostConstruct
    public void postConstruct() {
        updateObjectMapper(this.objectMapperRedis);
    }

    public static ObjectMapper updateObjectMapper(final ObjectMapper objectMapperRedis) {
        objectMapperRedis.setDefaultTyping(new StdTypeResolverBuilder().init(JsonTypeInfo.Id.CLASS, null).inclusion(JsonTypeInfo.As.PROPERTY));
        objectMapperRedis.addMixIn(PublicKeyCredentialRequestOptions.class, WebauthnPublicKeyCredentialRequestOptionsMixIn.class);
        objectMapperRedis.addMixIn(PublicKeyCredentialCreationOptions.class, WebauthnPublicKeyCredentialCreationOptionsMixIn.class);
        objectMapperRedis.addMixIn(Bytes.class, WebauthnBytesMixIn.class);

        final SimpleModule webauthnSerdesModule = new SimpleModule();
//        webauthnSerdesModule.addSerializer(PublicKeyCredentialRequestOptions.class, new GenericJsonSerializer<>(objectMapperRedis, PublicKeyCredentialRequestOptions.class));
//        webauthnSerdesModule.addDeserializer(PublicKeyCredentialRequestOptions.class, new GenericJsonDeserializer<>(objectMapperRedis, PublicKeyCredentialRequestOptions.class));
//        webauthnSerdesModule.addSerializer(PublicKeyCredentialCreationOptions.class, new GenericJsonSerializer<>(objectMapperRedis, PublicKeyCredentialCreationOptions.class));
//        webauthnSerdesModule.addDeserializer(PublicKeyCredentialCreationOptions.class, new GenericJsonDeserializer<>(objectMapperRedis, PublicKeyCredentialCreationOptions.class));
        webauthnSerdesModule.addSerializer(Bytes.class, new BytesSerializer());
        webauthnSerdesModule.addDeserializer(Bytes.class, new BytesDeserializer());
        objectMapperRedis.registerModule(webauthnSerdesModule);

        return objectMapperRedis;
    }
}
