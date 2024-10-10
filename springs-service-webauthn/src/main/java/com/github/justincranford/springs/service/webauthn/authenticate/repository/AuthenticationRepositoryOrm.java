package com.github.justincranford.springs.service.webauthn.authenticate.repository;

import java.util.concurrent.TimeUnit;

import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationRequest;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

@SuppressWarnings({"nls"})
public class AuthenticationRepositoryOrm {
	private final Cache<String, AuthenticationRequest> startedAuthentications = CacheBuilder.newBuilder().maximumSize(1000)
			.expireAfterAccess(1, TimeUnit.DAYS).build();

	public void add(final String sessionToken, final AuthenticationRequest registrationRequest) {
		this.startedAuthentications.put(sessionToken, registrationRequest);
	}

	public AuthenticationRequest remove(final String sessionToken) {
		final AuthenticationRequest registrationRequest = this.startedAuthentications.getIfPresent(sessionToken);
		if (registrationRequest == null) {
			throw new RuntimeException("Authentication does not exist");
		}
		this.startedAuthentications.invalidate(sessionToken);
		return registrationRequest;
	}
}
