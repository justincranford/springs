package com.github.justincranford.springs.persistenceorm.clients.client;

import java.util.Optional;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

public interface ClientOrmRepository extends ListCrudRepository<ClientOrm, Long>, RevisionRepository<ClientOrm, Long, Long> {
	Optional<ClientOrm> findByClientId(String clientid);
}