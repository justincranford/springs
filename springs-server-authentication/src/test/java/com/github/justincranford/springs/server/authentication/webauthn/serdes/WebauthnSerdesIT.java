package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;

import static com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnGivens.publicKeyCredentialCreationOptions;
import static com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnGivens.publicKeyCredentialRequestOptions;

@Slf4j
public class WebauthnSerdesIT extends AbstractIT {
    @Test
    void testSerdesBytes() throws JsonProcessingException {
        final Bytes bytes = Bytes.random();

        final String serialized = springSessionDefaultObjectMapper().writeValueAsString(bytes);
        log.info("Serialized: {}", serialized);

        final Bytes deserialized = springSessionDefaultObjectMapper().readValue(serialized, Bytes.class);
        log.info("Deserialized: {}\n", deserialized);
    }

    @Test
    void testSerdesPublicKeyCredentialCreationOptions() throws JsonProcessingException {
        final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = publicKeyCredentialCreationOptions();

        final String serialized = springSessionDefaultObjectMapper().writeValueAsString(publicKeyCredentialCreationOptions);
        log.info("Serialized: {}", serialized);

        final PublicKeyCredentialCreationOptions deserialized = springSessionDefaultObjectMapper().readValue(serialized, PublicKeyCredentialCreationOptions.class);
        log.info("Deserialized: {}\n", deserialized);
    }

    @Test
    void testSerdesPublicKeyCredentialRequestOptions() throws JsonProcessingException {
        final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions();

        final String serialized = springSessionDefaultObjectMapper().writeValueAsString(publicKeyCredentialRequestOptions);
        log.info("Serialized: {}", serialized);

        final PublicKeyCredentialRequestOptions deserialized = springSessionDefaultObjectMapper().readValue(serialized, PublicKeyCredentialRequestOptions.class);
        log.info("Deserialized: {}\n", deserialized);

    }
}
