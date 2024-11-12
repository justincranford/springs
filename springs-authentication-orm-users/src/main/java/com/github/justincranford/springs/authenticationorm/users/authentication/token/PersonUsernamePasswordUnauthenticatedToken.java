package com.github.justincranford.springs.authenticationorm.users.authentication.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

@SuppressWarnings({"hiding"})
public class PersonUsernamePasswordUnauthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;

	private final String username;
	private String password;
	public PersonUsernamePasswordUnauthenticatedToken(final String username, final String password) {
		super(null);
		this.username = username;
		this.password = password;
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
