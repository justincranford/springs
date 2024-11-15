package com.github.justincranford.springs.persistenceorm.sessions.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.persistenceorm.sessions.service.exception.PersonUsernameNotFoundException;
import com.github.justincranford.springs.persistenceorm.sessions.service.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.persistenceorm.sessions.service.model.PersonDetails;
import com.github.justincranford.springs.persistenceorm.users.config.projection.PersonIdPasswordProjection;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

import jakarta.persistence.OptimisticLockException;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class PersonService implements UserDetailsService {
	@Autowired
	private PersonOrmRepository personOrmRepository;

    @Transactional
	@Override
	public PersonDetails loadUserByUsername(final String usernameMixedCase) throws UsernameNotFoundException {
    	final String usernameLowerCase = usernameMixedCase.toLowerCase();
		final PersonOrm personOrm = this.personOrmRepository.findByUsername(usernameLowerCase).orElseThrow(() -> {
			log.debug("Person not found by username [{}]", usernameMixedCase);
			throw new PersonUsernameNotFoundException("Username not found");
		});
		log.trace("Person found by username, person: {}", personOrm);

		final List<PersonaOrm> personaOrms = personOrm.personas();
		if (personaOrms.isEmpty()) {
			log.trace("Personas not found by person: {}", personOrm);
			return new PersonDetails(personOrm, null);
		}

		final PersonaOrm personaOrm = personaOrms.getFirst();
		log.trace("Persona found by person, persona: {}", personaOrm);

		return new PersonDetails(personOrm, personaOrm);
	}

    @Transactional
    public PersonIdPasswordProjection findPersonIdPasswordByUsername(final String usernameMixedCase) throws UsernameNotFoundException {
    	final String usernameLowerCase = usernameMixedCase.toLowerCase();
		final PersonIdPasswordProjection personIdPasswordProjection = this.personOrmRepository.findPersonIdPasswordProjectionByUsername(usernameLowerCase).orElseThrow(() -> {
        	log.debug("Person id+password not found by username [{}]", usernameMixedCase);
        	throw new PersonaEmailNotFoundException("Username not found");
		});
		assert personIdPasswordProjection.getPersonId()       != null : "Person ID must be non-null";
		assert personIdPasswordProjection.getPersonPassword() != null : "Person password must be non-null";
    	log.trace("Person id+password found by username: {}", usernameMixedCase);
		return personIdPasswordProjection;
    }

    @Transactional // TODO Retries?
	public void updatePasswordById(final Long id, final String password) {
    	final int rowsUpdated = this.personOrmRepository.updatePasswordById(id, password, DateTimeUtil.nowUtcTruncatedToMicroseconds());
    	if (rowsUpdated != 0) {
    		log.error("Failed to update password for person, id: {}", id);
    		throw new OptimisticLockException("Failed to update password for person");
    	}
		log.trace("Updated password for person, id: {}", id);
	}
}
