package com.github.justincranford.springs.persistenceorm.clients.service;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrmRepository;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientProjectionIdSecret;
import com.github.justincranford.springs.persistenceorm.clients.client.exception.ClientClientNameNotFoundException;
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
	public ClientDetails loadUserByUsername(final String ClientNameMixedCase) throws UsernameNotFoundException {
    	final String ClientNameLowerCase = ClientNameMixedCase.toLowerCase();
		final ClientOrm clientOrm = this.clientOrmRepository.findByClientName(ClientNameLowerCase).orElseThrow(() -> {
			log.debug("Client not found by clientName [{}]", ClientNameMixedCase);
            return new ClientClientNameNotFoundException("clientName not found");
		});
		log.trace("Client found by clientName, client: {}", clientOrm);

		return new ClientDetails(ClientNameMixedCase, clientOrm.id(), clientOrm, true, true, true, true);
	}

    @Transactional
    public ClientProjectionIdSecret findClientNameSecretByClientName(final String ClientNameMixedCase) throws ClientClientNameNotFoundException {
    	final String ClientNameLowerCase = ClientNameMixedCase.toLowerCase();
		final ClientProjectionIdSecret clientProjectionIdSecret = this.clientOrmRepository.findClientProjectionIdSecretByClientName(ClientNameLowerCase).orElseThrow(() -> {
        	log.debug("Client id+secret not found by clientName [{}]", ClientNameMixedCase);
            return new ClientClientNameNotFoundException("clientName not found");
		});
		assert clientProjectionIdSecret.getId() != null : "Client ID must be non-null";
		assert clientProjectionIdSecret.getSecret() != null : "Client secret must be non-null";
    	log.trace("Client id+secret found by clientName: {}", ClientNameMixedCase);
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
