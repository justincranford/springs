package com.github.justincranford.springs.authenticationorm.users.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import com.github.justincranford.springs.persistenceorm.users.person.PasswordOrm;

@SuppressWarnings({"nls","hiding"})
public class PersonUsernamePasswordAuthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = 1L;

	private final String username;
	private PasswordOrm password;
	/*package*/ PersonUsernamePasswordAuthenticatedToken(final String username, final PasswordOrm password, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.username = username;
		this.password = password;
		super.setAuthenticated(true);
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
		Assert.isTrue(isAuthenticated, "Set false is not supported");
		super.setAuthenticated(true);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.password = null;
	}

}
