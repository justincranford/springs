package com.github.justincranford.springs.server.webauthn.credential.repository;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserIdentityRepositoryOrm extends ListCrudRepository<UserIdentityOrm,Long>, RevisionRepository<UserIdentityOrm,Long,Long> {
    Optional<UserIdentityOrm> findByUserHandle(byte[] userHandle);

    Optional<UserIdentityOrm> findByUsername(String username);
}
