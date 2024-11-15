package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.concurrent.Future;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.persistenceorm.sessions.service.PersonService;
import com.github.justincranford.springs.persistenceorm.sessions.service.util.LockUtil;
import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.github.justincranford.springs.util.basic.ThreadUtil.ThrowingSupplier;
import com.github.justincranford.springs.util.basic.Timer;

import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;

// TODO Move to springs-persistence-orm-users
@Component
@Observed
@Slf4j
public class PasswordUpgradeEncodingService {
	private final LockUtil<Long, Future<Void>> lockUtil = new LockUtil<>();

    @Autowired
	private PersonService personLookupService;

	@Autowired
    private PasswordEncoder passwordEncoder;

	@Observed
    public Future<Void> asyncUpdatePasswordByPersonId(final Long personId, final String personEncodedPassword) {
		// do encode and updatePassword asynchronously
    	final ThrowingSupplier<Void> innerSupplier = () -> encodeAndUpdateById(personId, personEncodedPassword);
		final Future<Void>           innerAsync    = ThreadUtil.supplyAsync(innerSupplier);

		// wrap inner async to avoid concurrent execution for same ID
		final Supplier<Future<Void>> outerSupplier = () -> innerAsync;
		final Future<Void>           outerAsync    = this.lockUtil.run(personId, outerSupplier);

		return outerAsync;
	}

	@Observed
	private Void encodeAndUpdateById(final Long personId, final String personEncodedPassword) {
		final String newEncodedPassword = this.encode(personEncodedPassword);
		this.updatePassword(personId, newEncodedPassword);
		return null;
	}

	@Observed
	private String encode(final String personEncodedPassword) {
		try (Timer x = Timer.go("PasswordUpgradeEncodingService.encode")) {
			return this.passwordEncoder.encode(personEncodedPassword); // design intent is slow
		}
	}

	@Observed
	private void updatePassword(final Long personId, final String newEncodedPassword) {
		try (Timer x = Timer.go("PasswordUpgradeEncodingService.updatePassword")) {
			this.personLookupService.updatePasswordById(personId, newEncodedPassword);
		}
	}
}
