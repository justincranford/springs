package com.github.justincranford.springs.server.authentication.client.token;

import com.nimbusds.jwt.JWT;
import lombok.Getter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.io.Serial;
import java.text.ParseException;

public class ClientJwtUnauthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	@Getter
	private JWT jwt;
	private final String name;

	public ClientJwtUnauthenticatedToken(final JWT _jwt) {
		super(null);
		this.jwt = _jwt;
		try {
			this.name = this.jwt.getJWTClaimsSet().getSubject();
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
		super.setAuthenticated(false);
	}

	@Override
	public Object getPrincipal() {
        return this.name;
    }

	@Override
	public Object getCredentials() {
		return this.jwt;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated, "Set true is not supported");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.jwt = null;
	}

}
