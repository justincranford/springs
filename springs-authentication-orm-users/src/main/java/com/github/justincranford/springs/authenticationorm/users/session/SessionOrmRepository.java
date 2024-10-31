package com.github.justincranford.springs.authenticationorm.users.session;

import java.util.Optional;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;

public interface SessionOrmRepository extends ListCrudRepository<SessionOrm, Long>, RevisionRepository<SessionOrm, Long, Long> {
	Optional<SessionOrm> findByExternalId(byte[] externalId);
	Optional<Long> getIdByExternalId(byte[] externalId);
}