package com.github.justincranford.springs.persistenceorm.clients.properties;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrmRepository;
import com.github.justincranford.springs.persistenceorm.clients.client.ClientPasswordOrm;
import jakarta.annotation.PostConstruct;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@SuppressWarnings({"unused"})
public class LoadClientsPropertiesIntoDatabase {
    @Autowired
    private SpringsPersistenceOrmClientsClientProperties clientProperties;
    @Autowired
    private ClientOrmRepository clientOrmRepository;

    @Transactional
    @PostConstruct
    public void loadUsers() {
        final List<SpringsPersistenceOrmClientsClientProperties.Client> clients = this.clientProperties.getClients();

        for (final SpringsPersistenceOrmClientsClientProperties.Client client : clients) {
            final ClientOrm createClientOrm = new ClientOrm();
            createClientOrm.clientId(client.getClientId());
            createClientOrm.password(new ClientPasswordOrm(client.getPassword()));
            createClientOrm.status(client.getStatus());
            createClientOrm.type(client.getType());
            createClientOrm.timezones(client.getTimezones());
            this.clientOrmRepository.save(createClientOrm);
        }
    }
}
