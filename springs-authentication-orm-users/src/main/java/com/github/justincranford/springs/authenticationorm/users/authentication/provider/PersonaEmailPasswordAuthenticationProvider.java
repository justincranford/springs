package com.github.justincranford.springs.authenticationorm.users.authentication.provider;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PersonaLookupService;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonaDetails;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordAuthenticatedToken;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordUnauthenticatedToken;

import lombok.extern.slf4j.Slf4j;

@Component
@SuppressWarnings({"nls"})
@Slf4j
public class PersonaEmailPasswordAuthenticationProvider implements AuthenticationProvider {
    private static final Class<?> SUPPORTED_TOKEN_CLASS = PersonaEmailPasswordUnauthenticatedToken.class;
	@Autowired
	private PersonaLookupService personaLookupService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public boolean supports(final Class<?> clazz) {
		return SUPPORTED_TOKEN_CLASS.equals(clazz);
    }

    @Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
    	if (unauthenticatedToken == null) {
    		return null;
    	} else if (!(this.supports(unauthenticatedToken.getClass()))) {
        	log.trace("Token not supported, class: {}", unauthenticatedToken.getClass());
    		return null;
		}

    	final PersonaEmailPasswordUnauthenticatedToken unauthenticatedEmailPasswordToken = (PersonaEmailPasswordUnauthenticatedToken) unauthenticatedToken;
		final String unauthenticatedRawEmail = unauthenticatedEmailPasswordToken.getName();
		final String unauthenticatedPassword = unauthenticatedEmailPasswordToken.getCredentials().toString();
		if (Strings.isBlank(unauthenticatedPassword)) {
        	log.trace("Password [{}] must not be blank", unauthenticatedPassword); // null, empty, or blank are not allowed
            throw new PersonaPasswordNoMatchException("Invalid password");
		}

		// ASSUME: loadUserByUsername will convert unauthenticatedRawEmail
		final PersonaDetails actualPersonaDetails = this.personaLookupService.loadUserByUsername(unauthenticatedRawEmail);
		if (this.passwordEncoder.matches(unauthenticatedPassword, actualPersonaDetails.getPassword())) {
	    	log.trace("Persona password matched for email [{}]", unauthenticatedRawEmail);
			return new PersonaEmailPasswordAuthenticatedToken(actualPersonaDetails);
        }
    	log.debug("Persona password not matched for email [{}]", unauthenticatedRawEmail);
        throw new PersonaPasswordNoMatchException("Invalid password");
    }
}
