package com.github.justincranford.springs.authenticationorm.users.authentication.token;

import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.sessions.database.util.CustomGrantedAuthority;
import com.github.justincranford.springs.persistenceorm.sessions.service.model.PersonDetails;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public class PersonUsernamePasswordAuthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;

	private PersonDetails personDetails;

	private List<CustomGrantedAuthority> authorities;

	public PersonUsernamePasswordAuthenticatedToken() {
		this(null);
	}

	public PersonUsernamePasswordAuthenticatedToken(final PersonDetails actualPersonDetails) {
		super(actualPersonDetails == null ? null : actualPersonDetails.getAuthorities());
		super.setAuthenticated(true);
		this.personDetails = actualPersonDetails;
		this.authorities = actualPersonDetails == null ? null : actualPersonDetails.getAuthorities();
	}

	@Override
	public Object getPrincipal() {
		return this.personDetails.getUsername();
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	@SuppressWarnings({"unchecked", "rawtypes"})
	public List<GrantedAuthority> getAuthorities() {
		return (List) this.authorities;
	}

	public void setAuthorities(final List<CustomGrantedAuthority> _authorities) {
		this.authorities = _authorities;
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
