package com.github.justincranford.springs.persistenceorm.clients.properties.service;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrmRepository;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientSecretOrm;
import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties;
import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties.Client;
import com.github.justincranford.springs.util.security.hashes.encoder.EncodeUtil;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

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
    public void loadClients() {
        final List<SpringsPersistenceOrmClientsClientProperties.Client> clients = this.clientProperties.getClient();
        final List<String> encodedSecrets = EncodeUtil.encode(this.passwordEncoder, clients.stream().map(Client::getSecret).toList());

        int clientOffset = 0;
        for (final SpringsPersistenceOrmClientsClientProperties.Client client : clients) {
            final ClientOrm createClientOrm = new ClientOrm();
            createClientOrm.name(client.getName());
            createClientOrm.secret(new ClientSecretOrm(encodedSecrets.get(clientOffset++)));
            createClientOrm.status(client.getStatus());
            createClientOrm.clientType(client.getClientType());
            createClientOrm.clientTimeZones(client.getTimeZones());
            this.clientOrmRepository.save(createClientOrm);
        }
    }
}
