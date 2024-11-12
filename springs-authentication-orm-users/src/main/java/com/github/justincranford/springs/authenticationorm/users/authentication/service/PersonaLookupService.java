package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.Optional;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonaDetails;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.EmailAddressRfc5321Orm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;

import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class PersonaLookupService implements UserDetailsService {
    @Autowired
    private PersonaOrmRepository personaOrmRepository;
    private EmailAddressRfc5321Orm.EmailConverter emailConverter = new EmailAddressRfc5321Orm.EmailConverter(); 

    @Transactional
	@Override
    public PersonaDetails loadUserByUsername(final String unauthenticatedRawEmail) throws UsernameNotFoundException {
		if (Strings.isBlank(unauthenticatedRawEmail)) {
        	log.trace("Email [{}] must not be blank", unauthenticatedRawEmail); // null, empty, or blank are not allowed
        	throw new PersonaEmailNotFoundException("Invalid email");
		}
		final String unauthenticatedConvertedEmail = this.emailConverter.convertToDatabaseColumn(unauthenticatedRawEmail);
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
}
