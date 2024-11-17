package com.github.justincranford.springs.server.webauthn.register.repository;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RegistrationRepositoryOrm extends ListCrudRepository<RegistrationOrm,Long>, RevisionRepository<RegistrationOrm,Long,Long> {
    Optional<RegistrationOrm> findBySessionToken(String SessionToken);
}
