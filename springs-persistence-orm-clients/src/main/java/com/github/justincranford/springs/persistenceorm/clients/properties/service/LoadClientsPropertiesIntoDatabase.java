package com.github.justincranford.springs.persistenceorm.clients.properties.service;

import java.util.List;

import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties;
import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties.Client;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrmRepository;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientSecretOrm;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeUtil;

import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;

@Service
public class LoadClientsPropertiesIntoDatabase {
	@Autowired
    private SpringsPersistenceOrmClientsClientProperties clientProperties;
    @Autowired
    private ClientOrmRepository clientOrmRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @Transactional
    @PostConstruct
    public void loadUsers() {
        final List<SpringsPersistenceOrmClientsClientProperties.Client> clients = this.clientProperties.getClients();
        final List<String> encodedSecrets = EncodeUtil.encode(this.passwordEncoder, clients.stream().map(Client::getSecret).toList());

        int userOffset = 0;
        for (final SpringsPersistenceOrmClientsClientProperties.Client client : clients) {
            final ClientOrm createClientOrm = new ClientOrm();
            createClientOrm.clientName(client.getClientName());
            createClientOrm.secret(new ClientSecretOrm(encodedSecrets.get(userOffset++)));
            createClientOrm.status(client.getStatus());
            createClientOrm.clientType(client.getClientType());
            createClientOrm.timezones(client.getTimezones());
            this.clientOrmRepository.save(createClientOrm);
        }
    }
}
