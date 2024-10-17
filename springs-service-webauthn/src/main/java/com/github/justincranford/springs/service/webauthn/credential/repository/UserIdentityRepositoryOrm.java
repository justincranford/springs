package com.github.justincranford.springs.service.webauthn.credential.repository;

import java.util.Optional;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserIdentityRepositoryOrm extends ListCrudRepository<UserIdentityOrm, Long>, RevisionRepository<UserIdentityOrm, Long, Long> {
	Optional<UserIdentityOrm> findByUserHandle(byte[] userHandle);
	Optional<UserIdentityOrm> findByUsername(String username);
}
