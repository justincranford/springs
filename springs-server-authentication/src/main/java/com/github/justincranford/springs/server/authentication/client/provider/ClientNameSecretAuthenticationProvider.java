package com.github.justincranford.springs.server.authentication.client.provider;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientProjectionIdSecret;
import com.github.justincranford.springs.persistenceorm.clients.client.model.ClientDetails;
import com.github.justincranford.springs.persistenceorm.clients.client.service.ClientSecretUpgradeEncodingService;
import com.github.justincranford.springs.persistenceorm.clients.client.service.ClientService;
import com.github.justincranford.springs.persistenceorm.users.persona.email.EmailRfc5321Validator;
import com.github.justincranford.springs.server.authentication.client.exception.ClientSecretBlankNotAllowedException;
import com.github.justincranford.springs.server.authentication.client.exception.ClientSecretNoMatchException;
import com.github.justincranford.springs.server.authentication.client.exception.ClientTokenClassNotSupportedException;
import com.github.justincranford.springs.server.authentication.client.exception.ClientTokenNullNotAllowedException;
import com.github.justincranford.springs.server.authentication.client.token.ClientNameSecretAuthenticatedToken;
import com.github.justincranford.springs.server.authentication.client.token.ClientNameSecretUnauthenticatedToken;
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

import static com.github.justincranford.springs.server.authentication.exception.AuthenticationExceptionUtil.logAndCreate;
import static org.slf4j.event.Level.DEBUG;
import static org.slf4j.event.Level.TRACE;

@Component
@Slf4j
public class ClientNameSecretAuthenticationProvider implements AuthenticationProvider {
	private static final EmailRfc5321Validator EMAIL_VALIDATOR = EmailRfc5321Validator.create(null);

	@Autowired
	private ClientService clientService;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private ClientSecretUpgradeEncodingService upgradeEncodingService;

    @Override
    public boolean supports(final Class<?> clazz) {
    	return ClientNameSecretUnauthenticatedToken.class.isAssignableFrom(clazz)
			   || UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
    }

    @Override
    public Authentication authenticate(final Authentication unauthenticatedToken) throws AuthenticationException {
        switch (unauthenticatedToken) {
            case ClientNameSecretUnauthenticatedToken ignored -> log.trace("Token class ClientNameSecretUnauthenticatedToken supported by ClientNameSecretAuthenticationProvider");
            case UsernamePasswordAuthenticationToken ignored -> log.trace("Token class UsernamePasswordAuthenticationToken supported by ClientNameSecretAuthenticationProvider");
            case null -> throw logAndCreate(ClientTokenNullNotAllowedException.class, DEBUG, "Token null not supported by ClientNameSecretAuthenticationProvider");
            default -> throw logAndCreate(ClientTokenClassNotSupportedException.class, TRACE, "Token class " + unauthenticatedToken.getClass().getSimpleName() + " not supported by ClientaEmailSecretAuthenticationProvider");
        }
		final String nameMixedCase = unauthenticatedToken.getName();
		final String secret        = unauthenticatedToken.getCredentials().toString();

		if (EMAIL_VALIDATOR.isValid(nameMixedCase, false)) {
			log.trace("Ignoring name [{}] because it is a valid email address.", nameMixedCase);
			return null; // ASSUME: Handled by PersonaEmailPasswordAuthenticationProvider
		} else if (Strings.isBlank(secret)) {
    		throw logAndCreate(ClientSecretBlankNotAllowedException.class, TRACE, "Secret must not be blank");
		}
		final String nameLowerCase = nameMixedCase.toLowerCase();

		final ClientProjectionIdSecret clientProjectionIdSecret;
		try (Timer ignored = Timer.go("clientService.findIdSecretByName")) {
			clientProjectionIdSecret = this.clientService.findIdSecretByName(nameLowerCase);
		}

		final boolean doesSecretMatch;
		try (Timer ignored = Timer.go("Client.passwordEncoder.matches", "passwordEncoder.matches")) {
			doesSecretMatch = this.passwordEncoder.matches(secret, clientProjectionIdSecret.getSecret());
		}
		if (doesSecretMatch) {
			if (this.passwordEncoder.upgradeEncoding(clientProjectionIdSecret.getSecret())) {
				log.debug("Client secret matched for name [{}]; upgrade encoding is required.", nameMixedCase);
				this.upgradeEncodingService.asyncUpdateSecretByName(clientProjectionIdSecret.getId(), secret);
			} else {
				log.trace("Client secret matched for name [{}]; upgrade encoding isn't required.", nameMixedCase);
			}
			final ClientDetails clientDetails;
			try (Timer ignored = Timer.go("clientService.loadUserByName")) {
				clientDetails = this.clientService.loadUserByUsername(nameMixedCase);
			}
			return new ClientNameSecretAuthenticatedToken(clientDetails);
		}
		throw logAndCreate(ClientSecretNoMatchException.class, DEBUG, String.format("Client secret not matched for name [%s]", nameMixedCase));
    }
}
