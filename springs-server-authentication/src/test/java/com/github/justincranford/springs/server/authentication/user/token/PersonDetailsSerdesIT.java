package com.github.justincranford.springs.server.authentication.user.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.MismatchedInputException;
import com.github.justincranford.springs.persistenceorm.users.person.model.PersonDetails;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

@Slf4j
public class PersonDetailsSerdesIT extends AbstractIT {
    @Test
    void testSerdes_springSessionDefaultObjectMapper_succeeds() {
        assertDoesNotThrow(() -> serdesHelper(springSessionDefaultObjectMapper()), "Expected no exception due to objectMapper.registerModules(SecurityJackson2Modules.getModules())");
    }

    @Test
    void testSerdes_objectMapper_fails() {
        final MismatchedInputException e = assertThrows(MismatchedInputException.class, () -> serdesHelper(objectMapper()));
        assertThat(e.getMessage()).startsWith("Cannot construct instance of `org.springframework.security.core.authority.SimpleGrantedAuthority`");
    }

    private static void serdesHelper(final ObjectMapper objectMapper) throws JsonProcessingException {
        final PersonDetails personDetails = PersonDetails.builder()
            .personId(1L)
            .personaId(2L)
            .enabled(true)
            .accountNonExpired(true)
            .accountNonLocked(true)
            .credentialsNonExpired(true)
            .authorities(List.of(
                new SimpleGrantedAuthority("ROLE_WHATEVER")
            ))
            .build();

        final String serialized = objectMapper.writeValueAsString(personDetails);
        log.info("Serialized: {}", serialized);

        final PersonDetails deserialized = objectMapper.readValue(serialized, PersonDetails.class);
        log.info("Deserialized: {}\n", deserialized);
    }
}
