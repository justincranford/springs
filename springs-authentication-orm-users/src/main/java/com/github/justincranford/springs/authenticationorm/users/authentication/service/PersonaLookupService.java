package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.Optional;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonaDetails;
import com.github.justincranford.springs.persistenceorm.users.person.PasswordOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class PersonaLookupService implements UserDetailsService, UserDetailsPasswordService {
    @Autowired
    private PersonaOrmRepository personaOrmRepository;

    @Transactional
	@Override
    public PersonaDetails loadUserByUsername(final String unauthenticatedRawEmail) throws UsernameNotFoundException {
		if (Strings.isBlank(unauthenticatedRawEmail)) {
        	log.trace("Email [{}] must not be blank", unauthenticatedRawEmail); // null, empty, or blank are not allowed
        	throw new PersonaEmailNotFoundException("Invalid email");
		}
		final String unauthenticatedConvertedEmail = unauthenticatedRawEmail.toLowerCase();
		if (unauthenticatedConvertedEmail.equals(unauthenticatedRawEmail)) {
        	log.trace("Email is [{}]", unauthenticatedConvertedEmail);
		} else {
        	log.debug("Email is [{}], converted from [{}]", unauthenticatedConvertedEmail, unauthenticatedRawEmail);
		}

        final Optional<PersonaOrm> optionalUnauthenticatedPersona = this.personaOrmRepository.findPersonaByEmailAddress(unauthenticatedConvertedEmail);
        if (optionalUnauthenticatedPersona.isPresent()) {
    		final PersonaOrm unauthenticatedPersona = optionalUnauthenticatedPersona.get();
        	log.trace("Persona found by email, persona: {}", unauthenticatedPersona);
            final PersonOrm  unauthenticatedPerson = unauthenticatedPersona.person();
        	log.trace("Person found by persona, person: {}", unauthenticatedPerson);

    		return new PersonaDetails(unauthenticatedPerson.username(), unauthenticatedPerson, unauthenticatedPersona);
        }
    	log.debug("Persona not found by email [{}]", unauthenticatedConvertedEmail);
    	throw new PersonaEmailNotFoundException("Invalid email");
    }

    @Transactional
	@Override
	public PersonaDetails updatePassword(final UserDetails userDetails, final String newPassword) {
    	if (!(userDetails instanceof PersonaDetails personaDetails)) {
    		throw new UnsupportedOperationException("UserDetails must be of type PersonaDetails");
    	}
    	personaDetails.personOrm().password(PasswordOrm.builder().password(newPassword).build());
    	return loadUserByUsername(personaDetails.getUsername());
	}
}
