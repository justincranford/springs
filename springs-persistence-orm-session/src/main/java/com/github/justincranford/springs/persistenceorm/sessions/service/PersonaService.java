package com.github.justincranford.springs.persistenceorm.sessions.service;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.persistenceorm.sessions.service.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.persistenceorm.sessions.service.model.PersonaDetails;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaProjectionIdAndPersonIdPassword;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

//TODO Move to springs-persistence-orm-users
@Service
@Slf4j
public class PersonaService implements UserDetailsService {
    private final PersonaOrmRepository personaOrmRepository;

    public PersonaService(final PersonaOrmRepository personaOrmRepository) {
        this.personaOrmRepository = personaOrmRepository;
    }

    @Transactional
	@Override
    public PersonaDetails loadUserByUsername(final String emailAddressMixedCase) throws UsernameNotFoundException {
        final String lowerCaseEmailAddress = emailAddressMixedCase.toLowerCase();
		final PersonaOrm personaOrm = this.personaOrmRepository.findByEmailAddress(lowerCaseEmailAddress).orElseThrow(() -> {
        	log.debug("Persona not found by email address [{}]", emailAddressMixedCase);
        	return new PersonaEmailNotFoundException("Email address not found");
		});
    	log.trace("Persona found by email address [{}]", personaOrm);

    	final PersonOrm personOrm = personaOrm.person();
    	log.trace("Person found by persona, person: {}", personOrm);

		return new PersonaDetails(emailAddressMixedCase, personOrm.id(), personOrm, personaOrm.id(), personaOrm, true, true, true, true);
    }

    @Transactional
    public PersonaProjectionIdAndPersonIdPassword findPersonaIdAndPersonIdPasswordByEmailAddress(final String emailAddressMixedCase) throws UsernameNotFoundException {
    	final String lowerCaseEmailAddress = emailAddressMixedCase.toLowerCase();
		final PersonaProjectionIdAndPersonIdPassword personaProjectionIdAndPersonIdPassword = this.personaOrmRepository.findPersonaIdAndPersonIdAndPasswordByEmailAddress(lowerCaseEmailAddress).orElseThrow(() -> {
        	log.debug("Persona ID and Person ID+password not found by email address [{}]", emailAddressMixedCase);
        	return new PersonaEmailNotFoundException("Email address not found");
		});
		assert personaProjectionIdAndPersonIdPassword.getId() != null : "Persona ID must be non-null";
		assert personaProjectionIdAndPersonIdPassword.getPersonId() != null : "Person ID must be non-null";
		assert personaProjectionIdAndPersonIdPassword.getPersonPassword() != null : "Person password must be non-null";
    	log.trace("Persona ID and Person ID+password found by email address [{}]", emailAddressMixedCase);
		return personaProjectionIdAndPersonIdPassword;
    }
}
