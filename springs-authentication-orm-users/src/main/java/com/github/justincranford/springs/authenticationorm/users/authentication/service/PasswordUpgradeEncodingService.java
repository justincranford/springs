package com.github.justincranford.springs.authenticationorm.users.authentication.service;

import java.util.concurrent.Future;
import java.util.function.Supplier;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.github.justincranford.springs.util.basic.ThreadUtil.ThrowingSupplier;
import com.github.justincranford.springs.util.basic.Timer;

import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;

@Component
@Observed
@Slf4j
public class PasswordUpgradeEncodingService {
	private final LockUtil<Long, Future<Boolean>> lockUtil = new LockUtil<>();

    @Autowired
	private PersonLookupService personLookupService;

	@Autowired
    private PasswordEncoder passwordEncoder;

    public Future<Boolean> async(final Long id, final String clearPassword) {
    	final ThrowingSupplier<Boolean> syncSupplier     = () -> sync(id, clearPassword);
		final Future<Boolean>           async            = ThreadUtil.supplyAsync(syncSupplier);
		final Supplier<Future<Boolean>> asyncSupplier    = () -> async;
		return this.lockUtil.run(id, asyncSupplier);
	}

	private boolean sync(final Long id, final String clearPassword) {
		final String newEncodedPassword;
		try (Timer x = Timer.go("PasswordUpgradeEncodingService.encode")) {
			newEncodedPassword = this.passwordEncoder.encode(clearPassword); // design intent is slow
		}
		try (Timer x = Timer.go("PasswordUpgradeEncodingService.updatePassword")) {
			this.personLookupService.updatePassword(id, newEncodedPassword);
		}
		return true;
	}
}
