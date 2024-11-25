package com.github.justincranford.springs.server.authentication.client.token;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.github.justincranford.springs.persistenceorm.clients.client.model.ClientDetails;
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
public class ClientNameSecretAuthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	@Getter
    private final ClientDetails clientDetails;

	@Setter
    private List<SimpleGrantedAuthority> authorities;

	public ClientNameSecretAuthenticatedToken() {
		this(null);
	}

	public ClientNameSecretAuthenticatedToken(final ClientDetails actualClientDetails) {
		super(actualClientDetails == null ? null : actualClientDetails.getAuthorities());
		super.setAuthenticated(true);
		this.clientDetails = actualClientDetails;
		this.authorities = actualClientDetails == null ? null : actualClientDetails.getAuthorities();
	}

	@Override
	public Object getPrincipal() {
		return this.clientDetails.name();
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
