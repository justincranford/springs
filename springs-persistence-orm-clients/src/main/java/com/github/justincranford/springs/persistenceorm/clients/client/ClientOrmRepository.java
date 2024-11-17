package com.github.justincranford.springs.persistenceorm.clients.client;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

import java.util.Optional;

@SuppressWarnings({"unused"})
public interface ClientOrmRepository extends ListCrudRepository<ClientOrm,Long>, RevisionRepository<ClientOrm,Long,Long> {
    Optional<ClientOrm> findByClientId(String clientid);
}
