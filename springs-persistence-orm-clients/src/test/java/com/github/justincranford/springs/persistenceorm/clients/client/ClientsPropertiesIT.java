package com.github.justincranford.springs.persistenceorm.clients.client;

import com.github.justincranford.springs.persistenceorm.clients.AbstractIT;
import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties;
import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties.Client;
import lombok.extern.slf4j.Slf4j;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

@Slf4j
public class ClientsPropertiesIT extends AbstractIT {
    @Test
    public void verifyClientsPropertiesLoaded() {
        final List<Client> clientsProperties = clientsProperties().getClients();
        Assertions.assertThat(clientsProperties).isNotNull();
        Assertions.assertThat(clientsProperties).isNotEmpty();
        Assertions.assertThat(clientsProperties).hasSize(3);
        for (final SpringsPersistenceOrmClientsClientProperties.Client clientProperties : clientsProperties) {
            log.info("client: {}", clientProperties);
        }
    }

    @Test
    public void verifyClientsOrmsLoaded() {
        final List<ClientOrm> clientOrms = clientOrmRepository().findAll();
        prettyJson().logAndSave(clientOrms);
        Assertions.assertThat(clientOrms).isNotNull();
        Assertions.assertThat(clientOrms).isNotEmpty();
        Assertions.assertThat(clientOrms).hasSize(3);
        for (final ClientOrm clientOrm : clientOrms) {
            prettyJson().logAndSave(clientOrm);
        }
    }
}
