package com.github.justincranford.springs.server.authentication.user.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.users.persona.model.PersonaDetails;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import java.io.Serial;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@SuppressWarnings({"unused"})
public class PersonaEmailPasswordAuthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

    private final String principal;

	public PersonaEmailPasswordAuthenticatedToken() {
		this(null);
	}

	public PersonaEmailPasswordAuthenticatedToken(final PersonaDetails _personaDetails) {
		super(_personaDetails == null ? null : _personaDetails.getAuthorities());
		super.setAuthenticated(true);
		this.principal = _personaDetails == null ? null : _personaDetails.getUsername();
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
