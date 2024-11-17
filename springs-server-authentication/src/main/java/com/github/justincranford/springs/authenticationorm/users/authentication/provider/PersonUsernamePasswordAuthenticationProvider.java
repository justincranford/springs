package com.github.justincranford.springs.authenticationorm.users.authentication.provider;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonPasswordBlankNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonTokenClassNotSupportedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonTokenNullNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PasswordUpgradeEncodingService;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonUsernamePasswordAuthenticatedToken;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonUsernamePasswordUnauthenticatedToken;
import com.github.justincranford.springs.persistenceorm.sessions.service.PersonService;
import com.github.justincranford.springs.persistenceorm.sessions.service.model.PersonDetails;
import com.github.justincranford.springs.persistenceorm.users.config.projection.PersonIdPasswordProjection;
import com.github.justincranford.springs.persistenceorm.users.persona.email.EmailRfc5321Validator;
import com.github.justincranford.springs.util.basic.Timer;
import lombok.extern.slf4j.Slf4j;
import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import static com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.AuthenticationExceptionUtil.logAndCreate;
import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.TRACE;

@Component
@Slf4j
public class PersonUsernamePasswordAuthenticationProvider implements AuthenticationProvider {
    private static final EmailRfc5321Validator EMAIL_VALIDATOR = EmailRfc5321Validator.create(null);

    @Autowired
    private PersonService personService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private PasswordUpgradeEncodingService upgradeEncodingService;

    @Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
        if (unauthenticatedToken instanceof PersonUsernamePasswordUnauthenticatedToken) {
            log.trace("Token class PersonaEmailPasswordUnauthenticatedToken supported by PersonUsernamePasswordAuthenticationProvider");
        } else if (unauthenticatedToken instanceof UsernamePasswordAuthenticationToken) {
            log.trace("Token class UsernamePasswordAuthenticationToken supported by PersonUsernamePasswordAuthenticationProvider");
        } else if (unauthenticatedToken == null) {
            throw logAndCreate(PersonTokenNullNotAllowedException.class, DEBUG, "Token null not supported by PersonaEmailPasswordAuthenticationProvider");
        } else {
            throw logAndCreate(PersonTokenClassNotSupportedException.class, TRACE, "Token class " + unauthenticatedToken.getClass().getSimpleName() + " not supported by PersonaEmailPasswordAuthenticationProvider");
        }
        final String usernameMixedCase = unauthenticatedToken.getName();
        final String password = unauthenticatedToken.getCredentials().toString();

        if (EMAIL_VALIDATOR.isValid(usernameMixedCase, false)) {
            log.trace("Ignoring name [{}] because it is a valid email address.", usernameMixedCase);
            return null; // ASSUME: Handled by PersonaEmailPasswordAuthenticationProvider
        } else if (Strings.isBlank(password)) {
            throw logAndCreate(PersonPasswordBlankNotAllowedException.class, TRACE, "Password must not be blank");
        }
        final String usernameLowerCase = usernameMixedCase.toLowerCase();

        final PersonIdPasswordProjection personIdPasswordProjection;
        try (Timer ignored = Timer.go("personService.findPersonIdPasswordByUsername")) {
            personIdPasswordProjection = this.personService.findPersonIdPasswordByUsername(usernameLowerCase);
        }

        final boolean doesPasswordMatch;
        try (Timer ignored = Timer.go("passwordEncoder.matches")) {
            doesPasswordMatch = this.passwordEncoder.matches(password, personIdPasswordProjection.getPersonPassword());
        }
        if (doesPasswordMatch) {
            if (this.passwordEncoder.upgradeEncoding(personIdPasswordProjection.getPersonPassword())) {
                log.debug("Person password matched for username [{}]; upgrade encoding is required.", usernameMixedCase);
                this.upgradeEncodingService.asyncUpdatePasswordByPersonId(personIdPasswordProjection.getPersonId(), password);
            } else {
                log.trace("Person password matched for username [{}]; upgrade encoding isn't required.", usernameMixedCase);
            }
            final PersonDetails personDetails;
            try (Timer ignored = Timer.go("personService.loadUserByUsername")) {
                personDetails = this.personService.loadUserByUsername(usernameMixedCase);
            }
            return new PersonUsernamePasswordAuthenticatedToken(personDetails);
        }
        throw logAndCreate(PersonPasswordNoMatchException.class, DEBUG, String.format("Person password not matched for username [%s]", usernameMixedCase));
    }

    @Override
    public boolean supports(final Class<?> clazz) {
        return PersonUsernamePasswordUnauthenticatedToken.class.isAssignableFrom(clazz)
               || UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
    }
}
