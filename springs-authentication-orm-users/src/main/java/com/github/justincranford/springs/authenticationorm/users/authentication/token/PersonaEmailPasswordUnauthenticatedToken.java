package com.github.justincranford.springs.authenticationorm.users.authentication.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

@SuppressWarnings({"hiding"})
public class PersonaEmailPasswordUnauthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;

	private final String emailAddress;
	private String password;
	public PersonaEmailPasswordUnauthenticatedToken(final String emailAddress, final String password) {
		super(null);
		this.emailAddress = emailAddress;
		this.password = password;
		super.setAuthenticated(false);
	}

	@Override
	public Object getPrincipal() {
		return this.emailAddress;
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
