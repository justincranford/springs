package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.concurrent.Future;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.github.justincranford.springs.util.basic.ThreadUtil.ThrowingSupplier;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class PasswordUpgradeEncodingService {
	private final LockUtil<Future<Boolean>> lockUtil = new LockUtil<>();

    @Autowired
	private PersonLookupService personLookupService;

	@Autowired
    private PasswordEncoder passwordEncoder;

    public Future<Boolean> async(final String username, final String clearAuthenticatedPassword, final String currentEncodedPassword) {
    	final ThrowingSupplier<Boolean> syncSupplier     = () -> sync(username, clearAuthenticatedPassword, currentEncodedPassword);
		final Future<Boolean>           async            = ThreadUtil.supplyAsync(syncSupplier);
		final Supplier<Future<Boolean>> asyncSupplier    = () -> async;
		return this.lockUtil.run(username, asyncSupplier);
	}

	private boolean sync(final String personUsername, final String clearAuthenticatedPassword, final String currentEncodedPassword) {
		final boolean upgradeEncoding = this.passwordEncoder.upgradeEncoding(currentEncodedPassword); // design intent is fast
		if (upgradeEncoding) {
			log.debug("Person password for username [{}] requires upgrade encoding", personUsername);
			final String newEncodedPassword = this.passwordEncoder.encode(clearAuthenticatedPassword); // design intent is slow
			this.personLookupService.updatePassword(personUsername, newEncodedPassword);
		} else {
			log.trace("Person password for username [{}] doesn't require upgrade encoding", personUsername);
		}
		return upgradeEncoding;
	}
}
