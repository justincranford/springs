package com.github.justincranford.springs.authenticationorm.users.authentication;

import java.util.List;
import java.util.Optional;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.authenticationorm.users.authentication.exception.PersonPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.exception.PersonUsernameNotFoundException;
import com.github.justincranford.springs.authenticationorm.users.authentication.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.persistenceorm.users.person.PasswordOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;

import lombok.extern.slf4j.Slf4j;

@Component
@SuppressWarnings({"nls"})
@Slf4j
public class PersonUsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private PersonOrmRepository personRepository;

	@Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
		if (!(unauthenticatedToken instanceof PersonaEmailPasswordUnauthenticatedToken unauthenticatedUsernamePasswordToken)) {
        	log.trace("Token not supported, class: {}", unauthenticatedToken.getClass());
			return null;
		}
        final String unauthenticatedUsername = unauthenticatedUsernamePasswordToken.getName();
        final String unauthenticatedPassword = unauthenticatedUsernamePasswordToken.getCredentials().toString();
		if (Strings.isBlank(unauthenticatedUsername)) {
        	log.trace("Username [{}] must not be blank", unauthenticatedUsername); // null, empty, or blank are not allowed
		} else if (Strings.isBlank(unauthenticatedPassword)) {
        	log.trace("Password [{}] must not be blank", unauthenticatedPassword); // null, empty, or blank are not allowed
		}

        final Optional<PersonOrm> optionalUnauthenticatedPerson = this.personRepository.findByUsername(unauthenticatedUsername);
        if (optionalUnauthenticatedPerson.isEmpty()) {
        	log.debug("Person not found by username [{}]", unauthenticatedUsername);
        	throw new PersonUsernameNotFoundException("Invalid email");
        }

        final PersonOrm unauthenticatedPerson = optionalUnauthenticatedPerson.orElseThrow(() -> new PersonaEmailNotFoundException("Invalid email"));
    	log.trace("Person found by username, person: {}", unauthenticatedPerson);
        final List<PersonaOrm> unauthenticatedPersonas = unauthenticatedPerson.personas();
    	log.trace("Personas found by person, personas: {}", unauthenticatedPersonas);
        final PersonaOrm unauthenticatedPersonaOrm = unauthenticatedPersonas.get(0);
    	log.trace("Persona found by person, persona: {}", unauthenticatedPersonaOrm);
		final PasswordOrm unauthenticatedPersonPassword = unauthenticatedPerson.password();
		if (this.passwordEncoder.matches(unauthenticatedPassword, unauthenticatedPersonPassword.password())) {
			final String personaTypeName = unauthenticatedPersonaOrm.personaType().name();
			final SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_" + personaTypeName);
			return new PersonaEmailPasswordAuthenticatedToken(unauthenticatedUsername, unauthenticatedPersonPassword, List.of(simpleGrantedAuthority));
        }
    	log.debug("Person password not matched for username [{}]", unauthenticatedUsername);
        throw new PersonPasswordNoMatchException("Invalid password");
    }

    @Override
    public boolean supports(final Class<?> clazz) {
        return PersonaEmailPasswordUnauthenticatedToken.class.equals(clazz);
    }
}
