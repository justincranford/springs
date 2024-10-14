package com.github.justincranford.springs.service.webauthn.register.repository;

import java.util.concurrent.TimeUnit;

import com.github.justincranford.springs.service.webauthn.register.data.RegistrationServerStart;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;

@SuppressWarnings({"nls"})
public class RegistrationRepositoryOrm {
	private final Cache<String, RegistrationServerStart> registrationServerStarts = CacheBuilder.newBuilder().maximumSize(1000)
			.expireAfterAccess(1, TimeUnit.DAYS).build();

	public void add(final String sessionToken, final RegistrationServerStart registrationServerStart) {
		this.registrationServerStarts.put(sessionToken, registrationServerStart);
	}

	public RegistrationServerStart remove(final String sessionToken) {
		final RegistrationServerStart registrationServerStart = this.registrationServerStarts.getIfPresent(sessionToken);
		if (registrationServerStart == null) {
			throw new RuntimeException("Request does not exist");
		}
		this.registrationServerStarts.invalidate(sessionToken);
		return registrationServerStart;
	}
}
