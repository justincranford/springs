package com.github.justincranford.springs.service.webauthn.register.repository;

import java.util.Optional;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface RegistrationRepositoryOrm extends ListCrudRepository<RegistrationOrm, Long>, RevisionRepository<RegistrationOrm, Long, Long> {
	Optional<RegistrationOrm> findBySessionToken(String SessionToken);
}

