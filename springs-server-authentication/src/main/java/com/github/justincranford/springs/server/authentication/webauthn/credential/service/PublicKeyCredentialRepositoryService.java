package com.github.justincranford.springs.server.authentication.webauthn.credential.service;

import com.github.justincranford.springs.server.authentication.webauthn.credential.repository.PublicKeyCredentialOrm;
import com.github.justincranford.springs.server.authentication.webauthn.credential.repository.PublicKeyCredentialRepositoryOrm;
import com.github.justincranford.springs.util.json.PrettyJson;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
public class PublicKeyCredentialRepositoryService implements UserCredentialRepository {
    @Autowired
    private PublicKeyCredentialRepositoryOrm publicKeyCredentialRepositoryOrm;

    @Autowired
    private PrettyJson prettyJson;

    @Transactional
    @Override
    public List<CredentialRecord> findByUserId(final Bytes userId) {
        try {
            log.info("Searching for WebAuthn publicKeyCredentialOrms by userId: {}", userId);
            final List<PublicKeyCredentialOrm> publicKeyCredentialOrms = this.publicKeyCredentialRepositoryOrm.findByUserEntityUserId(userId);
            log.info("Found {} WebAuthn publicKeyCredentialOrms by userId: {}, publicKeyCredentialOrms: {}", publicKeyCredentialOrms.size(), userId, this.prettyJson.pretty(publicKeyCredentialOrms));
            final List<CredentialRecord> credentialRecords = toCredentialRecords(publicKeyCredentialOrms);
            log.info("Returning WebAuthn credentialRecords by userId: {}, credentialRecords: {}", userId, this.prettyJson.pretty(credentialRecords));
            return credentialRecords;
        } catch (Exception e) {
            log.error("Error searching for WebAuthn credentialRecords by userId: {}", userId, e);
            throw e;
        }
    }

    @Transactional
    @Override
    public CredentialRecord findByCredentialId(final Bytes credentialId) {
        try {
            log.info("Searching for WebAuthn publicKeyCredentialOrm by credentialId: {}", credentialId);
            final PublicKeyCredentialOrm publicKeyCredentialOrm = this.publicKeyCredentialRepositoryOrm.findByCredentialId(credentialId);
            log.info("Found WebAuthn publicKeyCredentialOrm by credentialId: {}, publicKeyCredentialOrm: {}", credentialId, this.prettyJson.pretty(publicKeyCredentialOrm));
            final CredentialRecord credentialRecord = toCredentialRecord(publicKeyCredentialOrm);
            log.info("Returning WebAuthn credentialRecord by credentialId: {}, credentialRecord: {}", credentialId, this.prettyJson.pretty(credentialRecord));
            return credentialRecord;
        } catch (Exception e) {
            log.error("Error searching for WebAuthn credentialRecord by credentialId: {}", credentialId, e);
            throw e;
        }
    }

    @Transactional
    @Override
    public void save(final CredentialRecord credentialRecord) {
        try {
            log.info("Saving WebAuthn credentialRecord record: {}", this.prettyJson.pretty(credentialRecord));
            final PublicKeyCredentialOrm publicKeyCredentialOrm = toPublicKeyCredentialOrm(credentialRecord);
            log.info("Saving WebAuthn publicKeyCredentialOrm: {}", this.prettyJson.pretty(publicKeyCredentialOrm));
            final PublicKeyCredentialOrm savedPublicKeyCredentialOrm = this.publicKeyCredentialRepositoryOrm.save(publicKeyCredentialOrm);
            log.info("Saved WebAuthn publicKeyCredentialOrm: {}", this.prettyJson.pretty(savedPublicKeyCredentialOrm));
        } catch (Exception e) {
            log.error("Error saving credentialRecord: {}", this.prettyJson.pretty(credentialRecord), e);
            throw e;
        }
    }

    @Transactional
    @Override
    public void delete(final Bytes credentialId) {
        try {
            log.info("Deleting WebAuthn publicKeyCredentialOrm by credentialId: {}", credentialId);
            this.publicKeyCredentialRepositoryOrm.deleteByCredentialId(credentialId);
            log.info("Deleted WebAuthn publicKeyCredentialOrm by credentialId: {}", credentialId);
        } catch (Exception e) {
            log.error("Error deleting WebAuthn publicKeyCredentialOrm by credentialId: {}", credentialId, e);
            throw e;
        }
    }

    private static List<CredentialRecord> toCredentialRecords(final List<PublicKeyCredentialOrm> publicKeyCredentialOrm) {
        return publicKeyCredentialOrm.stream().map(PublicKeyCredentialRepositoryService::toCredentialRecord).toList();
    }

    private static CredentialRecord toCredentialRecord(final PublicKeyCredentialOrm publicKeyCredentialOrm) {
        if (publicKeyCredentialOrm == null) {
            return null;
        }
        return ImmutableCredentialRecord.builder()
            .credentialType(publicKeyCredentialOrm.credentialType())
            .credentialId(publicKeyCredentialOrm.credentialId())
            .publicKey(publicKeyCredentialOrm.publicKey())
            .signatureCount(publicKeyCredentialOrm.signatureCount())
            .uvInitialized(publicKeyCredentialOrm.isUvInitialized())
            .transports(publicKeyCredentialOrm.transports())
            .backupEligible(publicKeyCredentialOrm.backupEligible())
            .backupState(publicKeyCredentialOrm.backupState())
            .userEntityUserId(publicKeyCredentialOrm.userEntityUserId())
            .attestationObject(publicKeyCredentialOrm.attestationObject())
            .attestationClientDataJSON(publicKeyCredentialOrm.attestationClientDataJSON())
            .label(publicKeyCredentialOrm.label())
            .lastUsed(publicKeyCredentialOrm.lastUsed())
            .created(publicKeyCredentialOrm.created())
            .build();
    }

    private static PublicKeyCredentialOrm toPublicKeyCredentialOrm(final CredentialRecord credentialRecord) {
        if (credentialRecord == null) {
            return null;
        }
        return PublicKeyCredentialOrm.builder()
            .credentialType(credentialRecord.getCredentialType())
            .credentialId(credentialRecord.getCredentialId())
            .publicKey(credentialRecord.getPublicKey())
            .signatureCount(credentialRecord.getSignatureCount())
            .uvInitialized(credentialRecord.isUvInitialized())
            .transports(credentialRecord.getTransports())
            .backupEligible(credentialRecord.isBackupEligible())
            .backupState(credentialRecord.isBackupState())
            .userEntityUserId(credentialRecord.getUserEntityUserId())
            .attestationObject(credentialRecord.getAttestationObject())
            .attestationClientDataJSON(credentialRecord.getAttestationClientDataJSON())
            .label(credentialRecord.getLabel())
            .lastUsed(credentialRecord.getLastUsed())
            .created(credentialRecord.getCreated())
            .build();
    }
}
