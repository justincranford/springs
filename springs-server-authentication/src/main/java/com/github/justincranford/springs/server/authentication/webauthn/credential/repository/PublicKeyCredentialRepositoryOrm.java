package com.github.justincranford.springs.server.authentication.webauthn.credential.repository;

import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.history.RevisionRepository;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface PublicKeyCredentialRepositoryOrm extends ListCrudRepository<PublicKeyCredentialOrm, Long>, RevisionRepository<PublicKeyCredentialOrm, Long, Long> {
    PublicKeyCredentialOrm findByCredentialId(Bytes externalId);
    List<PublicKeyCredentialOrm> findByUserEntityUserId(Bytes userId);
    void deleteByCredentialId(Bytes externalId);
}
