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

import com.github.justincranford.springs.authenticationorm.users.authentication.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.authenticationorm.users.authentication.exception.PersonaPasswordNoMatchException;
import com.github.justincranford.springs.persistenceorm.users.person.PasswordOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.EmailAddressRfc5321Orm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;

import lombok.extern.slf4j.Slf4j;

@Component
@SuppressWarnings({"nls"})
@Slf4j
public class PersonaEmailPasswordAuthenticationProvider implements AuthenticationProvider {
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private PersonaOrmRepository personaRepository;

    private EmailAddressRfc5321Orm.EmailConverter emailConverter = new EmailAddressRfc5321Orm.EmailConverter(); 

	@Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
		if (!(unauthenticatedToken instanceof PersonaEmailPasswordUnauthenticatedToken unauthenticatedEmailPasswordToken)) {
        	log.trace("Token not supported, class: {}", unauthenticatedToken.getClass());
			return null;
		}
		final String unauthenticatedRawEmail = unauthenticatedEmailPasswordToken.getName();
		final String unauthenticatedPassword = unauthenticatedEmailPasswordToken.getCredentials().toString();
		if (Strings.isBlank(unauthenticatedRawEmail)) {
        	log.trace("Email [{}] must not be blank", unauthenticatedRawEmail); // null, empty, or blank are not allowed
		} else if (Strings.isBlank(unauthenticatedPassword)) {
        	log.trace("Password [{}] must not be blank", unauthenticatedPassword); // null, empty, or blank are not allowed
		}

		final String unauthenticatedConvertedEmail = this.emailConverter.convertToDatabaseColumn(unauthenticatedRawEmail);
		if (unauthenticatedConvertedEmail.equals(unauthenticatedToken.getName())) {
        	log.trace("Email is [{}]", unauthenticatedConvertedEmail);
		} else {
        	log.debug("Email is [{}], converted from [{}]", unauthenticatedConvertedEmail, unauthenticatedRawEmail);
		}

        final Optional<PersonaOrm> optionalUnauthenticatedPersona = this.personaRepository.findPersonaByEmailAddress(unauthenticatedConvertedEmail);
        if (optionalUnauthenticatedPersona.isEmpty()) {
        	log.debug("Persona not found by email [{}]", unauthenticatedConvertedEmail);
        	throw new PersonaEmailNotFoundException("Invalid email");
        }
		final PersonaOrm  unauthenticatedPersona = optionalUnauthenticatedPersona.get();
    	log.trace("Persona found by email, persona: {}", unauthenticatedPersona);
        final PersonOrm   unauthenticatedPerson = unauthenticatedPersona.person();
    	log.trace("Person found by persona, person: {}", unauthenticatedPerson);
		final PasswordOrm unauthenticatedPersonPassword = unauthenticatedPerson.password();
		if (this.passwordEncoder.matches(unauthenticatedPassword, unauthenticatedPersonPassword.password())) {
	    	log.trace("Persona password matched for email [{}]", unauthenticatedRawEmail);
			final String personaTypeName = unauthenticatedPersona.personaType().name();
			final SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority("ROLE_" + personaTypeName);
			return new PersonaEmailPasswordAuthenticatedToken(unauthenticatedConvertedEmail, unauthenticatedPersonPassword, List.of(simpleGrantedAuthority));
        }
    	log.debug("Persona password not matched for email [{}]", unauthenticatedRawEmail);
        throw new PersonaPasswordNoMatchException("Invalid password");
    }

    @Override
    public boolean supports(final Class<?> clazz) {
        return PersonaEmailPasswordUnauthenticatedToken.class.equals(clazz);
    }
}
