package com.github.justincranford.springs.server.authentication.client.token;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.util.Assert;

import java.io.Serial;
import java.text.ParseException;

@Slf4j
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
			if (_jwt instanceof SignedJWT) {
				this.name = this.jwt.getJWTClaimsSet().getSubject();
			} else if (_jwt instanceof EncryptedJWT) {
				this.name = "Unknown because EncryptedJWT";
			} else {
				throw new IllegalArgumentException("Invalid jwt " + _jwt);
			}
		} catch (ParseException e) {
			log.error("Unexpected exception", e);
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
