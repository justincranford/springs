package com.github.justincranford.springs.authenticationorm.users.authentication;

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import com.github.justincranford.springs.persistenceorm.users.person.PasswordOrm;

@SuppressWarnings({"nls","hiding"})
public class PersonaEmailPasswordAuthenticatedToken extends AbstractAuthenticationToken {
	private static final long serialVersionUID = -4662613398693032846L;

	public static PersonaEmailPasswordAuthenticatedToken authenticated(final String principal, final PasswordOrm password, final Collection<? extends GrantedAuthority> authorities) {
		return new PersonaEmailPasswordAuthenticatedToken(principal, password, authorities);
	}
	public static PersonaEmailPasswordAuthenticatedToken unauthenticated(final String principal, final PasswordOrm password) {
		return new PersonaEmailPasswordAuthenticatedToken(principal, password);
	}

	private final String emailAddress;
	private PasswordOrm password;
	private PersonaEmailPasswordAuthenticatedToken(final String emailAddress, final PasswordOrm password) {
		super(null);
		this.emailAddress = emailAddress;
		this.password = password;
		setAuthenticated(false);
	}
	private PersonaEmailPasswordAuthenticatedToken(final String emailAddress, final PasswordOrm password, Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
		this.emailAddress = emailAddress;
		this.password = password;
		super.setAuthenticated(true); // must use super, as we override
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
