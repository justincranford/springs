package com.github.justincranford.springs.authenticationorm.users.authentication.provider;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaPasswordBlankNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaPasswordNoMatchException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaTokenClassNotSupportedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.exception.PersonaTokenNullNotAllowedException;
import com.github.justincranford.springs.authenticationorm.users.authentication.service.PasswordUpgradeEncodingService;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordAuthenticatedToken;
import com.github.justincranford.springs.authenticationorm.users.authentication.token.PersonaEmailPasswordUnauthenticatedToken;
import com.github.justincranford.springs.persistenceorm.sessions.service.PersonaService;
import com.github.justincranford.springs.persistenceorm.sessions.service.exception.PersonaEmailNotFoundException;
import com.github.justincranford.springs.persistenceorm.sessions.service.model.PersonaDetails;
import com.github.justincranford.springs.persistenceorm.users.config.projection.PersonaIdAndPersonIdPasswordProjection;
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
@SuppressWarnings({"unused"})
public class PersonaEmailPasswordAuthenticationProvider implements AuthenticationProvider {
    private static final EmailRfc5321Validator EMAIL_VALIDATOR = EmailRfc5321Validator.create(null);

    @Autowired
    private PersonaService personaService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private PasswordUpgradeEncodingService upgradeEncodingService;

    @Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
        switch (unauthenticatedToken) {
            case PersonaEmailPasswordUnauthenticatedToken personaEmailPasswordUnauthenticatedToken ->
                log.trace("Token class PersonaEmailPasswordUnauthenticatedToken supported by PersonaEmailPasswordAuthenticationProvider");
            case UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken ->
                log.trace("Token class UsernamePasswordAuthenticationToken supported by PersonaEmailPasswordAuthenticationProvider");
            case null -> throw logAndCreate(PersonaTokenNullNotAllowedException.class, DEBUG, "Token null not supported by PersonaEmailPasswordAuthenticationProvider");
            default ->
                throw logAndCreate(PersonaTokenClassNotSupportedException.class, TRACE, "Token class " + unauthenticatedToken.getClass().getSimpleName() + " not supported by PersonaEmailPasswordAuthenticationProvider");
        }
        final String emailAddressMixedCase = unauthenticatedToken.getName();
        final String password = unauthenticatedToken.getCredentials().toString();

        if (!(EMAIL_VALIDATOR.isValid(emailAddressMixedCase, false))) {
            throw logAndCreate(PersonaEmailNotFoundException.class, TRACE, String.format("Name [%s] is not an email address.", emailAddressMixedCase));
        } else if (Strings.isBlank(password)) {
            throw logAndCreate(PersonaPasswordBlankNotAllowedException.class, DEBUG, "Password must not be blank");
        }
        final String emailAddressLowerCase = emailAddressMixedCase.toLowerCase();

        final PersonaIdAndPersonIdPasswordProjection personaIdAndPersonIdPasswordProjection;
        try (Timer ignored = Timer.go("personaLookupService.findPersonIdAndPasswordByEmailAddress")) {
            personaIdAndPersonIdPasswordProjection = this.personaService.findPersonaIdAndPersonIdPasswordByEmailAddress(emailAddressLowerCase);
        }

        final boolean doesPasswordMatch;
        try (Timer ignored = Timer.go("passwordEncoder.matches")) {
            doesPasswordMatch = this.passwordEncoder.matches(password, personaIdAndPersonIdPasswordProjection.getPersonPassword());
        }
        if (doesPasswordMatch) {
            if (this.passwordEncoder.upgradeEncoding(personaIdAndPersonIdPasswordProjection.getPersonPassword())) {
                log.debug("Person password matched for persona email address [{}]; upgrade encoding is required", emailAddressMixedCase);
                this.upgradeEncodingService.asyncUpdatePasswordByPersonId(personaIdAndPersonIdPasswordProjection.getPersonId(), password);
            } else {
                log.trace("Person password matched for persona email address [{}]; upgrade encoding isn't required", emailAddressMixedCase);
            }
            final PersonaDetails personaDetails;
            try (Timer ignored = Timer.go("personaService.findPersonaByEmailAddress")) {
                personaDetails = this.personaService.loadUserByUsername(emailAddressLowerCase);
            }
            return new PersonaEmailPasswordAuthenticatedToken(personaDetails);
        }
        throw logAndCreate(PersonaPasswordNoMatchException.class, DEBUG, String.format("Person password doesn't match for persona email address [%s]", emailAddressMixedCase));
    }

    @Override
    public boolean supports(final Class<?> clazz) {
        return PersonaEmailPasswordUnauthenticatedToken.class.isAssignableFrom(clazz)
               || UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
    }
}
