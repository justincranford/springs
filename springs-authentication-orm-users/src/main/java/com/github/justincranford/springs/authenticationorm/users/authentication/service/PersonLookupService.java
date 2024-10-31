package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.Optional;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonUsernameNotFoundException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonDetails;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls"})
public class PersonLookupService implements UserDetailsService {
	@Autowired
	private PersonOrmRepository personOrmRepository;

	@Override
	public PersonDetails loadUserByUsername(final String unauthenticatedUsername) throws UsernameNotFoundException {
		if (Strings.isBlank(unauthenticatedUsername)) {
			log.trace("Username [{}] must not be blank", unauthenticatedUsername); // null, empty, or blank are not
			throw new PersonaEmailNotFoundException("Invalid username");
		}

		final Optional<PersonOrm> optionalUnauthenticatedPerson = this.personOrmRepository.findByUsername(unauthenticatedUsername);
		if (optionalUnauthenticatedPerson.isEmpty()) {
			log.debug("Person not found by username [{}]", unauthenticatedUsername);
			throw new PersonUsernameNotFoundException("Invalid username");
		}

		final PersonOrm unauthenticatedPerson = optionalUnauthenticatedPerson.get();
		log.trace("Person found by username, person: {}", unauthenticatedPerson);

		final PersonaOrm unauthenticatedPersona = unauthenticatedPerson.personas().get(0);
		log.trace("Persona found by person, persona: {}", unauthenticatedPersona);

		return new PersonDetails(unauthenticatedPerson, unauthenticatedPersona);
	}
}
