package com.github.justincranford.springs.service.webauthn.register.repository;

import java.util.concurrent.TimeUnit;

import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

@SuppressWarnings({"nls"})
public class RegistrationRepositoryOrm {
	private final Cache<String, RegistrationRequest> startedRegistrations = CacheBuilder.newBuilder().maximumSize(1000)
			.expireAfterAccess(1, TimeUnit.DAYS).build();

	public void add(final String sessionToken, final RegistrationRequest registrationRequest) {
		this.startedRegistrations.put(sessionToken, registrationRequest);
	}

	public RegistrationRequest remove(final String sessionToken) {
		final RegistrationRequest registrationRequest = this.startedRegistrations.getIfPresent(sessionToken);
		if (registrationRequest == null) {
			throw new RuntimeException("Request does not exist");
		}
		this.startedRegistrations.invalidate(sessionToken);
		return registrationRequest;
	}
}
