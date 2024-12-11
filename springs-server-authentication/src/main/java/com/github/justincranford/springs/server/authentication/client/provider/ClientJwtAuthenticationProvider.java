package com.github.justincranford.springs.server.authentication.client.provider;

import com.github.justincranford.springs.persistenceorm.clients.client.model.ClientDetails;
import com.github.justincranford.springs.persistenceorm.clients.client.service.ClientService;
import com.github.justincranford.springs.persistenceorm.users.persona.email.EmailRfc5321Validator;
import com.github.justincranford.springs.server.authentication.client.exception.ClientTokenClassNotSupportedException;
import com.github.justincranford.springs.server.authentication.client.exception.ClientTokenNullNotAllowedException;
import com.github.justincranford.springs.server.authentication.client.service.JwtIssuerService;
import com.github.justincranford.springs.server.authentication.client.token.BearerUnauthenticatedToken;
import com.github.justincranford.springs.server.authentication.client.token.ClientJwtAuthenticatedToken;
import com.github.justincranford.springs.util.basic.Timer;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

import java.text.ParseException;

import static com.github.justincranford.springs.server.authentication.exception.AuthenticationExceptionUtil.logAndCreate;
import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.TRACE;

@Component
@Slf4j
public class ClientJwtAuthenticationProvider implements AuthenticationProvider {
	private static final EmailRfc5321Validator EMAIL_VALIDATOR = EmailRfc5321Validator.create(null);

	@Autowired
	private ClientService clientService;

	@Autowired
	private JwtIssuerService jwtIssuerService;

    @Override
    public boolean supports(final Class<?> clazz) {
    	return BearerUnauthenticatedToken.class.isAssignableFrom(clazz);
    }

    @Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
        switch (unauthenticatedToken) {
            case BearerUnauthenticatedToken ignored -> log.trace("Token class ClientJwtUnauthenticatedToken supported by ClientJwtAuthenticationProvider");
            case null -> throw logAndCreate(ClientTokenNullNotAllowedException.class, DEBUG, "Token null not supported by ClientJwtAuthenticationProvider");
            default -> throw logAndCreate(ClientTokenClassNotSupportedException.class, TRACE, "Token class " + unauthenticatedToken.getClass().getSimpleName() + " not supported by ClientJwtAuthenticationProvider");
        }
		final BearerUnauthenticatedToken bearerUnauthenticatedToken = (BearerUnauthenticatedToken) unauthenticatedToken;
        final String bearerToken = bearerUnauthenticatedToken.getBearer();
        if (bearerToken == null) {
            throw logAndCreate(AuthenticationCredentialsNotFoundException.class, DEBUG, "Unexpected null bearer token passed into ClientJwtAuthenticationProvider");
        } else if (bearerToken.isEmpty()) {
            throw logAndCreate(AuthenticationCredentialsNotFoundException.class, DEBUG, "Unexpected empty bearer token passed into ClientJwtAuthenticationProvider");
        } else if (bearerToken.isBlank()) {
            throw logAndCreate(AuthenticationCredentialsNotFoundException.class, DEBUG, "Unexpected blank bearer token passed into ClientJwtAuthenticationProvider");
        }
        final JWT jwt;
        try {
            jwt = JWTParser.parse(bearerToken);  // PlainJWT, SignedJWT, or EncryptedJWT
        } catch (ParseException e) {
            throw logAndCreate(BadCredentialsException.class, DEBUG, "Bearer token is not a JWT");
        }
		final JWT authenticatedJwt = this.jwtIssuerService.authenticate(jwt); // Only validates SignedJWT or EncryptedJWT, rejects PlainJWT

        final String nameMixedCase;
        try {
            nameMixedCase = authenticatedJwt.getJWTClaimsSet().getSubject();
        } catch (ParseException e) {
            throw new RuntimeException(e); // TODO Specific exception
        }
        if (EMAIL_VALIDATOR.isValid(nameMixedCase, false)) {
			log.trace("Ignoring name [{}] because it is a valid email address.", nameMixedCase);
			return null; // ASSUME: Handled by PersonaEmailPasswordAuthenticationProvider
		}

		final ClientDetails clientDetails;
		try (Timer ignored = Timer.go("clientService.loadUserByName")) {
			clientDetails = this.clientService.loadUserByUsername(nameMixedCase);
		}
		return new ClientJwtAuthenticatedToken(clientDetails, authenticatedJwt);
    }
}
