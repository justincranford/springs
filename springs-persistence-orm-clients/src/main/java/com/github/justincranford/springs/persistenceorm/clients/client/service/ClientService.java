package com.github.justincranford.springs.persistenceorm.clients.client.service;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrmRepository;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientProjectionIdSecret;
import com.github.justincranford.springs.persistenceorm.clients.client.exception.ClientNameNotFoundException;
import com.github.justincranford.springs.persistenceorm.clients.client.model.ClientDetails;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import jakarta.persistence.OptimisticLockException;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class ClientService implements UserDetailsService {
	@Autowired
	private ClientOrmRepository clientOrmRepository;

    @Transactional
	@Override
	public ClientDetails loadUserByUsername(final String nameMixedCase) throws UsernameNotFoundException {
    	final String nameLowerCase = nameMixedCase.toLowerCase();
		final ClientOrm clientOrm = this.clientOrmRepository.findByName(nameLowerCase).orElseThrow(() -> {
			log.debug("Client not found by name [{}]", nameMixedCase);
            return new ClientNameNotFoundException("name not found");
		});
		log.trace("Client found by name, client: {}", clientOrm);

		return new ClientDetails(nameMixedCase, clientOrm.id(), clientOrm, true, true, true, true);
	}

    @Transactional
    public ClientProjectionIdSecret findIdSecretByName(final String nameMixedCase) throws ClientNameNotFoundException {
    	final String nameLowerCase = nameMixedCase.toLowerCase();
		final ClientProjectionIdSecret clientProjectionIdSecret = this.clientOrmRepository.findClientProjectionIdSecretByName(nameLowerCase).orElseThrow(() -> {
        	log.debug("Client id+secret not found by name [{}]", nameMixedCase);
            return new ClientNameNotFoundException("name not found");
		});
		assert clientProjectionIdSecret.getId() != null : "Client ID must be non-null";
		assert clientProjectionIdSecret.getSecret() != null : "Client secret must be non-null";
    	log.trace("Client id+secret found by name: {}", nameMixedCase);
		return clientProjectionIdSecret;
    }

    @Transactional // TODO Retries?
	public void updateSecretById(final Long id, final String secret) {
    	final int rowsUpdated = this.clientOrmRepository.updateSecretById(id, secret, DateTimeUtil.nowUtcTruncatedToMicroseconds());
    	if (rowsUpdated < 1) {
    		log.error("Failed to update secret for client, id: {}", id);
    		throw new OptimisticLockException("Failed to update secret for client");
    	}
		log.trace("Updated secret for client, id: {}", id);
	}
}
