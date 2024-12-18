package com.github.justincranford.springs.server.authentication.user.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
public class PersonaEmailPasswordAuthenticatedTokenSerdesIT extends AbstractIT {
    @Test
    void testSerdes() throws JsonProcessingException {
        final PersonaEmailPasswordAuthenticatedToken original = new PersonaEmailPasswordAuthenticatedToken();

        final String serialized = objectMapper().writeValueAsString(original);
        log.info("Serialized: {}", serialized);

        final PersonaEmailPasswordAuthenticatedToken deserialized = objectMapper().readValue(serialized, PersonaEmailPasswordAuthenticatedToken.class);
        log.info("Deserialized: {}\n", deserialized);
    }
}
