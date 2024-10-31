package com.github.justincranford.springs.authenticationorm.users.authentication.provider;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PersonLookupService;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonDetails;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonUsernamePasswordAuthenticatedToken;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonUsernamePasswordUnauthenticatedToken;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordUnauthenticatedToken;

import lombok.extern.slf4j.Slf4j;

@Component
@SuppressWarnings({ "nls" })
@Slf4j
public class PersonUsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    private static final Class<?> SUPPORTED_TOKEN_CLASS = PersonaEmailPasswordUnauthenticatedToken.class;
	@Autowired
	private PersonLookupService personLookupService;
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

		final PersonUsernamePasswordUnauthenticatedToken unauthenticatedUsernamePasswordToken = (PersonUsernamePasswordUnauthenticatedToken) unauthenticatedToken;
		final String unauthenticatedUsername = unauthenticatedUsernamePasswordToken.getName();
		final String unauthenticatedPassword = unauthenticatedUsernamePasswordToken.getCredentials().toString();
		if (Strings.isBlank(unauthenticatedPassword)) {
			log.trace("Password [{}] must not be blank", unauthenticatedPassword); // null, empty, or blank are not allowed
			throw new PersonaPasswordNoMatchException("Invalid password");
		}

		final PersonDetails actualPersonDetails = this.personLookupService.loadUserByUsername(unauthenticatedUsername);
		if (this.passwordEncoder.matches(unauthenticatedPassword, actualPersonDetails.getPassword())) {
			log.trace("Person password matched for username [{}]", unauthenticatedUsername);
			return new PersonUsernamePasswordAuthenticatedToken(actualPersonDetails);
		}
		log.debug("Person password not matched for username [{}]", unauthenticatedUsername);
		throw new PersonPasswordNoMatchException("Invalid password");
	}
}
