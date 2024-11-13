package com.github.justincranford.springs.authenticationorm.users.authentication.provider;

import static com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.AuthenticationExceptionUtil.logAndCreate;
import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.TRACE;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaPasswordBlankNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaTokenClassNotSupportedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaTokenNullNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PasswordUpgradeEncodingService;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PersonaLookupService;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonaDetails;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordAuthenticatedToken;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordUnauthenticatedToken;
import com.github.justincranford.springs.util.basic.Timer;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class PersonaEmailPasswordAuthenticationProvider implements AuthenticationProvider {
	@Autowired
	private PersonaLookupService personaLookupService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private PasswordUpgradeEncodingService upgradeEncodingService;

    @Override
    public boolean supports(final Class<?> clazz) {
    	return PersonaEmailPasswordUnauthenticatedToken.class.isAssignableFrom(clazz)
			|| UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
    }

    @Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
		final String unauthenticatedRawEmail;
		final String unauthenticatedPassword;
    	if (unauthenticatedToken == null) {
    		throw logAndCreate(PersonaTokenNullNotAllowedException.class, TRACE, String.format("Token is null"));
    	} else if (unauthenticatedToken instanceof PersonaEmailPasswordUnauthenticatedToken unauthenticatedEmailPasswordToken) {
        	log.trace("Token class [{}] supported", PersonaEmailPasswordUnauthenticatedToken.class.getSimpleName());
    		unauthenticatedRawEmail = unauthenticatedEmailPasswordToken.getName();
    		unauthenticatedPassword = unauthenticatedEmailPasswordToken.getCredentials().toString();
    	} else if (unauthenticatedToken instanceof UsernamePasswordAuthenticationToken unauthenticatedUsernamePasswordToken) {
        	log.trace("Token class [{}] supported", UsernamePasswordAuthenticationToken.class.getSimpleName());
    		unauthenticatedRawEmail = unauthenticatedUsernamePasswordToken.getName();
    		unauthenticatedPassword = unauthenticatedUsernamePasswordToken.getCredentials().toString();
    	} else {
    		throw logAndCreate(PersonaTokenClassNotSupportedException.class, TRACE, String.format("Token class [%s] not supported", unauthenticatedToken.getClass().getSimpleName()));
		}

		if (Strings.isBlank(unauthenticatedPassword)) {
    		throw logAndCreate(PersonaPasswordBlankNotAllowedException.class, TRACE, "Password must not be blank");
		}

		// ASSUME: loadUserByUsername will apply converter to unauthenticatedRawEmail to make it lowercase
		final PersonaDetails actualPersonaDetails;
		try (Timer x = Timer.go("personaLookupService.loadUserByUsername")) {
			actualPersonaDetails = this.personaLookupService.loadUserByUsername(unauthenticatedRawEmail);
		}
		final String actualEncodedPassword = actualPersonaDetails.getPassword();
		final boolean matches;
		try (Timer x = Timer.go("passwordEncoder.matches")) {
			matches = this.passwordEncoder.matches(unauthenticatedPassword, actualEncodedPassword);
		}
		if (matches) {
	    	log.trace("Person password matched for persona email [{}]", unauthenticatedRawEmail);
			this.upgradeEncodingService.async(actualPersonaDetails.personOrm().id(), unauthenticatedPassword, actualEncodedPassword);
	    	final boolean upgradeEncoding = this.passwordEncoder.upgradeEncoding(unauthenticatedPassword); // design intent is fast
			if (upgradeEncoding) {
				log.debug("Person password for persona email [{}] requires upgrade encoding", unauthenticatedRawEmail);
				this.upgradeEncodingService.async(actualPersonaDetails.personOrm().id(), unauthenticatedPassword, actualEncodedPassword);
			} else {
				log.trace("Person password for persona email [{}] doesn't require upgrade encoding", unauthenticatedRawEmail);
			}
			return new PersonaEmailPasswordAuthenticatedToken(actualPersonaDetails);
        }
		throw logAndCreate(PersonaPasswordNoMatchException.class, DEBUG, String.format("Persona password not matched for email [%s]", unauthenticatedRawEmail));
    }
}
