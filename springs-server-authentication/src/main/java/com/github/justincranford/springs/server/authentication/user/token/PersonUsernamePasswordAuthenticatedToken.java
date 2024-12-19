package com.github.justincranford.springs.server.authentication.user.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.users.person.model.PersonDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.io.Serial;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@SuppressWarnings({"unused"})
public class PersonUsernamePasswordAuthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	private final String principal;

	public PersonUsernamePasswordAuthenticatedToken() {
		this(null);
	}

	public PersonUsernamePasswordAuthenticatedToken(final PersonDetails actualPersonDetails) {
		super(actualPersonDetails == null ? null : actualPersonDetails.getAuthorities());
		super.setAuthenticated(true);
		this.principal = actualPersonDetails == null ? null : actualPersonDetails.getUsername();
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
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
}
