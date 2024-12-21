package com.github.justincranford.springs.persistenceorm.users.persona.service;

import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaProjectionIdAndPersonIdPassword;
import com.github.justincranford.springs.persistenceorm.users.persona.enums.PersonaType;
import com.github.justincranford.springs.persistenceorm.users.persona.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.persistenceorm.users.persona.model.PersonaDetails;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

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

		final PersonaType personaType = personaOrm.personaType();
		assert personaType != null;
		final List<GrantedAuthority> authorities = List.of(new SimpleGrantedAuthority("ROLE_" + personaType.name()));
		return new PersonaDetails(emailAddressMixedCase, personOrm.id(), personaOrm.id(), authorities, true, true, true, true);
    }

    @Transactional
    public PersonaProjectionIdAndPersonIdPassword findPersonaIdAndPersonIdPasswordByEmailAddress(final String emailAddressMixedCase) throws UsernameNotFoundException {
    	final String lowerCaseEmailAddress = emailAddressMixedCase.toLowerCase();
		final PersonaProjectionIdAndPersonIdPassword personaProjectionIdAndPersonIdPassword = this.personaOrmRepository.findPersonaIdAndPersonIdAndPasswordByEmailAddress(lowerCaseEmailAddress).orElseThrow(() -> {
        	log.warn("Persona ID and Person ID+password not found by email address [{}]", emailAddressMixedCase);
        	return new PersonaEmailNotFoundException("Email address not found");
		});
		log.info("Persona ID and Person ID+password found by email address [{}]", emailAddressMixedCase);
		assert personaProjectionIdAndPersonIdPassword.getId() != null : "Persona ID must be non-null";
		assert personaProjectionIdAndPersonIdPassword.getPersonId() != null : "Person ID must be non-null";
		assert personaProjectionIdAndPersonIdPassword.getPersonPassword() != null : "Person password must be non-null";
		return personaProjectionIdAndPersonIdPassword;
    }
}
