package com.github.justincranford.springs.server.authentication.user.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;

@Slf4j
public class PersonUsernamePasswordAuthenticatedTokenSerdesIT extends AbstractIT {

    @Test
    void testSerdes() throws JsonProcessingException {
        final PersonUsernamePasswordAuthenticatedToken original = new PersonUsernamePasswordAuthenticatedToken();

        final String serialized = objectMapper().writeValueAsString(original);
        log.info("Serialized: {}", serialized);

        final PersonUsernamePasswordAuthenticatedToken deserialized = objectMapper().readValue(serialized, PersonUsernamePasswordAuthenticatedToken.class);
        log.info("Deserialized: {}\n", deserialized);
    }
}
