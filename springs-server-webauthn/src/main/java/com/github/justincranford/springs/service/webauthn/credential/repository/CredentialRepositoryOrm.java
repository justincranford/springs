package com.github.justincranford.springs.service.webauthn.credential.repository;

import java.util.List;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialRepositoryOrm extends ListCrudRepository<CredentialOrm, Long>, RevisionRepository<CredentialOrm, Long, Long> {
	List<CredentialOrm> findByUserIdentityOrderByCreatedDateDesc(UserIdentityOrm userIdentityOrm);
	List<CredentialOrm> findByCredentialIdOrderByCreatedDateDesc(String credentialId);
}
