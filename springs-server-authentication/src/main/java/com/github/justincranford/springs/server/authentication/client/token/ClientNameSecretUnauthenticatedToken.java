package com.github.justincranford.springs.server.authentication.client.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.io.Serial;

public class ClientNameSecretUnauthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	private final String clientName;
	private String secret;
	public ClientNameSecretUnauthenticatedToken(final String _clientName, final String _secret) {
		super(null);
		this.clientName = _clientName;
		this.secret = _secret;
		super.setAuthenticated(false);
	}

	@Override
	public Object getPrincipal() {
		return this.clientName;
	}

	@Override
	public Object getCredentials() {
		return this.secret;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated, "Set true is not supported");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.secret = null;
	}

}
