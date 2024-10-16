package com.github.justincranford.springs.service.webauthn.credential.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CredentialRepositoryOrm extends ListCrudRepository<CredentialOrm, Long>, RevisionRepository<CredentialOrm, Long, Long> {
	Optional<String>    findUsernameByUserHandle(String userHandle);
	Optional<String>    findUserHandleByUsername(String username);

	List<CredentialOrm> findByUsernameOrderByCreatedDateDesc(String username);
	List<CredentialOrm> findByUserHandleOrderByCreatedDateDesc(String userHandle);
	List<CredentialOrm> findByCredentialIdOrderByCreatedDateDesc(String credentialId);
	List<CredentialOrm> findByCredentialIdAndUserHandleOrderByCreatedDateDesc(String credentialId, String userHandle);
}
