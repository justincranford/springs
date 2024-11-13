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

    public Future<Boolean> async(final Long id, final String clearPassword, final String encodedPassword) {
    	final ThrowingSupplier<Boolean> syncSupplier     = () -> sync(id, clearPassword, encodedPassword);
		final Future<Boolean>           async            = ThreadUtil.supplyAsync(syncSupplier);
		final Supplier<Future<Boolean>> asyncSupplier    = () -> async;
		return this.lockUtil.run(id, asyncSupplier);
	}

	private boolean sync(final Long id, final String clearPassword, final String encodedPassword) {
		final boolean upgradeEncoding = true;
//		try (Timer x = Timer.go("upgradeEncoding")) {
//			upgradeEncoding = true;//this.passwordEncoder.upgradeEncoding(currentEncodedPassword); // design intent is fast
//		}
		if (upgradeEncoding) {
			log.debug("Person password for username [{}] requires upgrade encoding", id);
			final String newEncodedPassword;
			try (Timer x = Timer.go("encode")) {
				newEncodedPassword = this.passwordEncoder.encode(clearPassword); // design intent is slow
			}
			try (Timer x = Timer.go("updatePassword")) {
				this.personLookupService.updatePassword(id, newEncodedPassword);
			}
		} else {
			log.trace("Person password for username [{}] doesn't require upgrade encoding", id);
		}
		return upgradeEncoding;
	}
}
