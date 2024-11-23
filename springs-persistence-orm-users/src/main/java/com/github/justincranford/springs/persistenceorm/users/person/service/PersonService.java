package com.github.justincranford.springs.persistenceorm.users.person.service;

import java.util.List;

import com.github.justincranford.springs.persistenceorm.users.persona.enums.PersonaType;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.persistenceorm.users.person.exception.PersonUsernameNotFoundException;
import com.github.justincranford.springs.persistenceorm.users.persona.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.persistenceorm.users.person.model.PersonDetails;
import com.github.justincranford.springs.persistenceorm.users.person.PersonProjectionIdPassword;
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
            return new PersonUsernameNotFoundException("Username not found");
		});
		log.trace("Person found by username, person: {}", personOrm);

		final List<PersonaOrm> personaOrms = personOrm.personas();
		if (personaOrms.isEmpty()) {
			log.trace("Personas not found by person: {}", personOrm);
			return new PersonDetails(usernameMixedCase, personOrm.id(), null, List.of(), true, true, true, true);
		}

		final PersonaOrm personaOrm = personaOrms.getFirst();
		log.trace("Persona found by person, persona: {}", personaOrm);

		final PersonaType personaType = personaOrm.personaType();
		assert personaType != null;
		final List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + personaType.name()));
		return new PersonDetails(usernameMixedCase, personOrm.id(), personaOrm.id(), authorities, true, true, true, true);
	}

    @Transactional
    public PersonProjectionIdPassword findPersonIdPasswordByUsername(final String usernameMixedCase) throws UsernameNotFoundException {
    	final String usernameLowerCase = usernameMixedCase.toLowerCase();
		final PersonProjectionIdPassword personProjectionIdPassword = this.personOrmRepository.findPersonProjectionIdPasswordByUsername(usernameLowerCase).orElseThrow(() -> {
        	log.debug("Person id+password not found by username [{}]", usernameMixedCase);
            return new PersonaEmailNotFoundException("Username not found");
		});
		assert personProjectionIdPassword.getId() != null : "Person ID must be non-null";
		assert personProjectionIdPassword.getPassword() != null : "Person password must be non-null";
    	log.trace("Person id+password found by username: {}", usernameMixedCase);
		return personProjectionIdPassword;
    }

    @Transactional // TODO Retries?
	public void updatePasswordById(final Long id, final String password) {
    	final int rowsUpdated = this.personOrmRepository.updatePasswordById(id, password, DateTimeUtil.nowUtcTruncatedToMicroseconds());
    	if (rowsUpdated < 1) {
    		log.error("Failed to update password for person, id: {}", id);
    		throw new OptimisticLockException("Failed to update password for person");
    	}
		log.trace("Updated password for person, id: {}", id);
	}
}
