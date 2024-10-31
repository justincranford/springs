package com.github.justincranford.springs.authenticationorm.users.authentication.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonaDetails;

@SuppressWarnings({"nls","hiding"})
public class PersonaEmailPasswordAuthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;

	private final PersonaDetails personaDetails;
	public PersonaEmailPasswordAuthenticatedToken(final PersonaDetails personaDetails) {
		super(personaDetails.getAuthorities());
		super.setAuthenticated(true);
		this.personaDetails = personaDetails;
	}

	@Override
	public Object getPrincipal() {
		return this.personaDetails.getUsername(); // email address
	}

	@Override
	public Object getCredentials() {
		return this.personaDetails.getPassword();
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (!isAuthenticated) {
			throw new UnsupportedOperationException("Set false is not supported in " + this.getClass().getSimpleName());
		}
		super.setAuthenticated(true);
	}

	public PersonaDetails getPersonaDetails() {
		return this.personaDetails;
	}
}
