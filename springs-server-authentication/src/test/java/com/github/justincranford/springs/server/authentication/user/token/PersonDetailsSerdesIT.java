package com.github.justincranford.springs.server.authentication.user.token;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.persistenceorm.users.person.model.PersonDetails;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

@Slf4j
public class PersonDetailsSerdesIT extends AbstractIT {
    @Test
    void testSerdes() throws JsonProcessingException {
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

        final String serialized = objectMapper().writeValueAsString(personDetails);
        log.info("Serialized: {}", serialized);

        final PersonDetails deserialized = objectMapper().readValue(serialized, PersonDetails.class);
        log.info("Deserialized: {}\n", deserialized);
    }
}
