package com.github.justincranford.springs.server.authentication.user.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.io.Serial;

public class PersonUsernamePasswordUnauthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	private final String username;
	private String password;
	public PersonUsernamePasswordUnauthenticatedToken(final String _username, final String _password) {
		super(null);
		this.username = _username;
		this.password = _password;
		super.setAuthenticated(false);
	}

	@Override
	public Object getPrincipal() {
		return this.username;
	}

	@Override
	public Object getCredentials() {
		return this.password;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated, "Set true is not supported");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.password = null;
	}

}
