package com.github.justincranford.springs.server.authentication.user.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.io.Serial;

public class PersonaEmailPasswordUnauthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	private final String principal;
	private String credentials;
	public PersonaEmailPasswordUnauthenticatedToken(final String _emailAddress, final String _password) {
		super(null);
		this.principal = _emailAddress;
		this.credentials = _password;
		super.setAuthenticated(false);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return this.credentials;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated, "Set true is not supported");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.credentials = null;
	}
}
