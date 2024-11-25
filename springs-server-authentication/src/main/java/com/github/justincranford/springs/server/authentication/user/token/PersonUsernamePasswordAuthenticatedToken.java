package com.github.justincranford.springs.server.authentication.user.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.users.person.model.PersonDetails;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.io.Serial;
import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
@SuppressWarnings({"unused"})
public class PersonUsernamePasswordAuthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	@Getter
    private final PersonDetails personDetails;

	@Setter
    private List<SimpleGrantedAuthority> authorities;

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

    @Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (!isAuthenticated) {
			throw new UnsupportedOperationException("Set false is not supported in " + this.getClass().getSimpleName());
		}
		super.setAuthenticated(true);
	}

}
