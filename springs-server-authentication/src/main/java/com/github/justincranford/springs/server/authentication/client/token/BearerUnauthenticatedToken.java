package com.github.justincranford.springs.server.authentication.client.token;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.io.Serial;

@Getter
@Slf4j
public class BearerUnauthenticatedToken extends AbstractAuthenticationToken {
	@Serial
	private static final long serialVersionUID = 1L;

	private String bearer;

	public BearerUnauthenticatedToken(final String _bearer) {
		super(null);
		this.bearer = _bearer;
		super.setAuthenticated(false);
	}

	@Override
	public Object getPrincipal() {
        return "Bearer";
    }

	@Override
	public Object getCredentials() {
		return this.bearer;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		Assert.isTrue(!isAuthenticated, "Set true is not supported");
		super.setAuthenticated(false);
	}

	@Override
	public void eraseCredentials() {
		super.eraseCredentials();
		this.bearer = null;
	}

}
