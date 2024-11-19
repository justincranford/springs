package com.github.justincranford.springs.persistenceorm.clients.service;

import com.github.justincranford.springs.persistenceorm.users.util.LockUtil;
import com.github.justincranford.springs.util.basic.ThreadUtil;
import com.github.justincranford.springs.util.basic.ThreadUtil.ThrowingSupplier;
import com.github.justincranford.springs.util.basic.Timer;
import io.micrometer.observation.annotation.Observed;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.concurrent.Future;
import java.util.function.Supplier;

@Component
@Observed
@Slf4j
public class ClientSecretUpgradeEncodingService {
	private final LockUtil<Long, Future<Void>> lockUtil = new LockUtil<>();

    @Autowired
	private ClientService clientService;

	@Autowired
    private PasswordEncoder passwordEncoder;

	@Observed
    public Future<Void> asyncUpdateSecretByClientName(final Long clientName, final String clientEncodedSecret) {
		// do encode and updateSecret asynchronously
    	final ThrowingSupplier<Void> innerSupplier = () -> encodeAndUpdateById(clientName, clientEncodedSecret);
		final Future<Void>           innerAsync    = ThreadUtil.supplyAsync(innerSupplier);

		// wrap inner async to avoid concurrent execution for same ID
		final Supplier<Future<Void>> outerSupplier = () -> innerAsync;
		final Future<Void>           outerAsync    = this.lockUtil.run(clientName, outerSupplier);

		return outerAsync;
	}

	@Observed
	private Void encodeAndUpdateById(final Long clientName, final String clientEncodedSecret) {
		final String newEncodedSecret = this.encode(clientEncodedSecret);
		this.updateSecret(clientName, newEncodedSecret);
		return null;
	}

	@Observed
	private String encode(final String clientEncodedSecret) {
		try (Timer ignored = Timer.go("SecretUpgradeEncodingService.encode")) {
			return this.passwordEncoder.encode(clientEncodedSecret); // design intent is slow
		}
	}

	@Observed
	private void updateSecret(final Long clientName, final String newEncodedSecret) {
		try (Timer ignored = Timer.go("SecretUpgradeEncodingService.updateSecret")) {
			this.clientService.updateSecretById(clientName, newEncodedSecret);
		}
	}
}
