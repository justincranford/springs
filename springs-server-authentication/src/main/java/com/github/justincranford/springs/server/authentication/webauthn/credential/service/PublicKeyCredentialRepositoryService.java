package com.github.justincranford.springs.server.authentication.webauthn.credential.service;

import com.github.justincranford.springs.server.authentication.webauthn.credential.repository.PublicKeyCredentialOrm;
import com.github.justincranford.springs.server.authentication.webauthn.credential.repository.PublicKeyCredentialRepositoryOrm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class PublicKeyCredentialRepositoryService implements UserCredentialRepository {
    @Autowired
    private PublicKeyCredentialRepositoryOrm publicKeyCredentialRepositoryOrm;

    @Override
    public void delete(final Bytes credentialId) {
        this.publicKeyCredentialRepositoryOrm.deleteByCredentialId(credentialId);
    }

    @Override
    public void save(final CredentialRecord credentialRecord) {
        this.publicKeyCredentialRepositoryOrm.save(
            PublicKeyCredentialOrm.builder()
                .credentialType(credentialRecord.getCredentialType())
                .credentialId(credentialRecord.getCredentialId())
                .publicKey(credentialRecord.getPublicKey())
                .signatureCount(credentialRecord.getSignatureCount())
                .transports(credentialRecord.getTransports())
                .backupEligible(credentialRecord.isBackupEligible())
                .backupState(credentialRecord.isBackupState())
                .userEntityUserId(credentialRecord.getUserEntityUserId())
                .attestationObject(credentialRecord.getAttestationObject())
                .attestationClientDataJSON(credentialRecord.getAttestationClientDataJSON())
                .label(credentialRecord.getLabel())
                .lastUsed(credentialRecord.getLastUsed())
                .created(credentialRecord.getCreated())
                .build()
        );
    }

    @Override
    public CredentialRecord findByCredentialId(final Bytes credentialId) {
        return this.publicKeyCredentialRepositoryOrm.findByCredentialId(credentialId);
    }

    @Override
    public List<CredentialRecord> findByUserId(final Bytes userId) {
        return this.publicKeyCredentialRepositoryOrm.findByUserEntityUserId(userId).stream().map(CredentialRecord.class::cast).toList();
    }
}
