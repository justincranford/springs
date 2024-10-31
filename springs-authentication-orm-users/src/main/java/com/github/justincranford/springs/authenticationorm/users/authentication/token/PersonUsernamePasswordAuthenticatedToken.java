package com.github.justincranford.springs.authenticationorm.users.authentication.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;

import com.github.justincranford.springs.authenticationorm.users.authentication.service.model.PersonDetails;

@SuppressWarnings({"nls"})
public class PersonUsernamePasswordAuthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;

	private final PersonDetails personDetails;
	public PersonUsernamePasswordAuthenticatedToken(final PersonDetails actualPersonDetails) {
		super(actualPersonDetails.getAuthorities());
		super.setAuthenticated(true);
		this.personDetails = actualPersonDetails;
	}

	@Override
	public Object getPrincipal() {
		return this.personDetails.getUsername();
	}

	@Override
	public Object getCredentials() {
		return this.personDetails.getPassword();
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (!isAuthenticated) {
			throw new UnsupportedOperationException("Set false is not supported in " + this.getClass().getSimpleName());
		}
		super.setAuthenticated(true);
	}

	public PersonDetails getPersonDetails() {
		return this.personDetails;
	}
}
