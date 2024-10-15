package com.github.justincranford.springs.service.webauthn.register.repository;

import java.util.concurrent.TimeUnit;

import com.github.justincranford.springs.service.webauthn.register.data.RegistrationStartServer;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

@SuppressWarnings({"nls"})
public class RegistrationRepositoryOrm {
	private final Cache<String, RegistrationStartServer> registrationStartServers = CacheBuilder.newBuilder().maximumSize(1000)
			.expireAfterAccess(1, TimeUnit.DAYS).build();

	public void add(final String sessionToken, final RegistrationStartServer registrationStartServer) {
		this.registrationStartServers.put(sessionToken, registrationStartServer);
	}

	public RegistrationStartServer remove(final String sessionToken) {
		final RegistrationStartServer registrationStartServer = this.registrationStartServers.getIfPresent(sessionToken);
		if (registrationStartServer == null) {
			throw new RuntimeException("Request does not exist");
		}
		this.registrationStartServers.invalidate(sessionToken);
		return registrationStartServer;
	}
}
