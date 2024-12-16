package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceredis.sessions.config.SpringsPersistenceRedisSessionsClientServerConfiguration;
import com.github.justincranford.springs.server.authentication.webauthn.config.SpringsServerAuthenticationWebauthnConfiguration;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.Collections;
import java.util.List;

public final class SerializationMain {
    private SerializationMain() { }

    public static void main(String[] args) throws Exception {
        SpringsPersistenceRedisSessionsClientServerConfiguration x = new SpringsPersistenceRedisSessionsClientServerConfiguration();
        ObjectMapper objectMapper = SpringsServerAuthenticationWebauthnConfiguration.updateObjectMapper(x.objectMapperRedis());

        // Create an example PublicKeyCredentialRequestOptions object
        PublicKeyCredentialRequestOptions options = PublicKeyCredentialRequestOptions.builder()
            .challenge(new Bytes("example-challenge".getBytes()))
            .timeout(Duration.ofSeconds(60))
            .rpId("example.com")
            .allowCredentials(Collections.emptyList())
            .userVerification(UserVerificationRequirement.PREFERRED)
            .extensions(new AuthenticationExtensionsClientInputs() {
                @Override
                public List<AuthenticationExtensionsClientInput> getInputs() {
                    return List.of();
                }
            })
            .build();

        // Serialize to JSON
        String json = objectMapper.writeValueAsString(options);
        System.out.println("Serialized JSON: " + json);

        // Deserialize back to an object
        PublicKeyCredentialRequestOptions deserialized = objectMapper.readValue(
            json, PublicKeyCredentialRequestOptions.class
        );
        System.out.println("Deserialized object: " + deserialized.getRpId());
    }
}
