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

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonPasswordBlankNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonTokenClassNotSupportedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonTokenNullNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PasswordUpgradeEncodingService;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PersonLookupService;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonDetails;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonUsernamePasswordAuthenticatedToken;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonUsernamePasswordUnauthenticatedToken;
import com.github.justincranford.springs.util.basic.Timer;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class PersonUsernamePasswordAuthenticationProvider implements AuthenticationProvider {
	@Autowired
	private PersonLookupService personLookupService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private PasswordUpgradeEncodingService upgradeEncodingService;

    @Override
    public boolean supports(final Class<?> clazz) {
    	return PersonUsernamePasswordUnauthenticatedToken.class.isAssignableFrom(clazz)
			|| UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
    }

    @Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
		final String unauthenticatedUsername;
		final String unauthenticatedPassword;
    	if (unauthenticatedToken == null) {
    		throw logAndCreate(PersonTokenNullNotAllowedException.class, TRACE, String.format("Token is null"));
    	} else if (unauthenticatedToken instanceof PersonUsernamePasswordUnauthenticatedToken unauthenticatedEmailPasswordToken) {
        	log.trace("Token class [{}] supported", PersonUsernamePasswordUnauthenticatedToken.class.getSimpleName());
    		unauthenticatedUsername = unauthenticatedEmailPasswordToken.getName();
    		unauthenticatedPassword = unauthenticatedEmailPasswordToken.getCredentials().toString();
    	} else if (unauthenticatedToken instanceof UsernamePasswordAuthenticationToken unauthenticatedUsernamePasswordToken) {
        	log.trace("Token class [{}] supported", UsernamePasswordAuthenticationToken.class.getSimpleName());
    		unauthenticatedUsername = unauthenticatedUsernamePasswordToken.getName();
    		unauthenticatedPassword = unauthenticatedUsernamePasswordToken.getCredentials().toString();
    	} else {
    		throw logAndCreate(PersonTokenClassNotSupportedException.class, TRACE, String.format("Token class [%s] not supported", unauthenticatedToken.getClass().getSimpleName()));
		}

		if (Strings.isBlank(unauthenticatedPassword)) {
    		throw logAndCreate(PersonPasswordBlankNotAllowedException.class, TRACE, "Password must not be blank");
		}

		final PersonDetails actualPersonDetails;
		try (Timer x = Timer.go("personLookupService.loadUserByUsername")) {
			actualPersonDetails = this.personLookupService.loadUserByUsername(unauthenticatedUsername);
		}
		final String actualEncodedPassword = actualPersonDetails.getPassword();
		final boolean matches;
		try (Timer x = Timer.go("personLookupService.matches")) {
			matches = this.passwordEncoder.matches(unauthenticatedPassword, actualEncodedPassword);
		}
		if (matches) {
	    	log.trace("Person password matched for person username [{}]", unauthenticatedUsername);
			this.upgradeEncodingService.async(actualPersonDetails.personOrm().username(), unauthenticatedPassword, actualEncodedPassword);
			return new PersonUsernamePasswordAuthenticatedToken(actualPersonDetails);
		}
		throw logAndCreate(PersonPasswordNoMatchException.class, DEBUG, String.format("Person password not matched for username [%s]", unauthenticatedUsername));
    }
}
