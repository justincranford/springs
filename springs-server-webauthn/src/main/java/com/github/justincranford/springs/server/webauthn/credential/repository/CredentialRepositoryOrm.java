package com.github.justincranford.springs.server.webauthn.credential.repository;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface CredentialRepositoryOrm extends ListCrudRepository<CredentialOrm,Long>, RevisionRepository<CredentialOrm,Long,Long> {
    List<CredentialOrm> findByUserIdentityOrderByCreatedDateDesc(UserIdentityOrm userIdentityOrm);

    List<CredentialOrm> findByCredentialIdOrderByCreatedDateDesc(String credentialId);
}
