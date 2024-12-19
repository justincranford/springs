package com.github.justincranford.springs.server.authentication.user.token;

import com.github.justincranford.springs.persistenceorm.users.person.model.PersonDetails;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;
import org.springframework.session.data.redis.RedisSessionRepository;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class RedisHttpSessionSerializationIT extends AbstractIT {
//    @Autowired
//    private SessionRepository<? extends Session> sessionRepository;
    @Autowired
    private RedisSessionRepository sessionRepository;

    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void testSecurityContextSerialization() {
        final PersonDetails personDetails = PersonDetails.builder().username("admin1").authorities(List.of(new SimpleGrantedAuthority("ROLE_ADM"))).build();
        final PersonUsernamePasswordAuthenticatedToken authentication = new PersonUsernamePasswordAuthenticatedToken(personDetails);

        final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(authentication);

        final Session session = this.sessionRepository.createSession();
        session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);
        ((SessionRepository)this.sessionRepository).save(session);

        // Retrieve and validate the SecurityContext
        final Session retrievedSession = this.sessionRepository.findById(session.getId());
        assertThat(retrievedSession).isNotNull();

        final Object storedContext = retrievedSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        assertThat(storedContext).isInstanceOf(SecurityContext.class);
        final SecurityContext storedContext1 = (SecurityContext) storedContext;
        assertThat(storedContext1.getAuthentication()).isInstanceOf(PersonUsernamePasswordAuthenticatedToken.class);

        final PersonUsernamePasswordAuthenticatedToken retrievedAuth = (PersonUsernamePasswordAuthenticatedToken) storedContext1.getAuthentication();
        assertThat(retrievedAuth.getPrincipal()).isEqualTo("admin1");
        assertThat(retrievedAuth.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsExactly("ROLE_ADM");
    }
}
