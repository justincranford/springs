package com.github.justincranford.springs.server.webauthn.authenticate.repository;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthenticationRepositoryOrm extends ListCrudRepository<AuthenticationOrm,Long>, RevisionRepository<AuthenticationOrm,Long,Long> {
    Optional<AuthenticationOrm> findBySessionToken(String SessionToken);
}
