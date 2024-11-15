package com.github.justincranford.springs.service.webauthn.authenticate.repository;

import java.util.Optional;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthenticationRepositoryOrm extends ListCrudRepository<AuthenticationOrm, Long>, RevisionRepository<AuthenticationOrm, Long, Long> {
	Optional<AuthenticationOrm> findBySessionToken(String SessionToken);
}

