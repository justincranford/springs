package com.github.justincranford.springs.authenticationorm.users.authentication.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonaDetails;

public class PersonaEmailPasswordAuthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;

	private final PersonaDetails personaDetails;
	public PersonaEmailPasswordAuthenticatedToken(final PersonaDetails _personaDetails) {
		super(_personaDetails.getAuthorities());
		super.setAuthenticated(true);
		this.personaDetails = _personaDetails;
	}

	@Override
	public Object getPrincipal() {
		return this.personaDetails.getUsername(); // email address
	}

	@Override
	public Object getCredentials() {
		return null;
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
