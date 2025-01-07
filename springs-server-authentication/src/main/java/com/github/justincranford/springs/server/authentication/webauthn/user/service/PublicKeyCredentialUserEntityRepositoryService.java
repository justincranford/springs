package com.github.justincranford.springs.server.authentication.webauthn.user.service;

import com.github.justincranford.springs.persistenceorm.users.person.NameOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonStatusType;
import com.github.justincranford.springs.util.json.PrettyJson;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;

import java.security.MessageDigest;

//@Service
@Slf4j
public class PublicKeyCredentialUserEntityRepositoryService implements PublicKeyCredentialUserEntityRepository {
    public static final String ANONYMOUS_USER = "anonymousUser";

    @Autowired
    private PersonOrmRepository personOrmRepository;

    @Autowired
    private PrettyJson prettyJson;

//    private ConcurrentHashMap<byte[], PublicKeyCredentialUserEntity> anonymousUsers = new ConcurrentHashMap<>();
    private PublicKeyCredentialUserEntity anonymousUser;

    @Transactional
    @Override
    public PublicKeyCredentialUserEntity findById(final Bytes userId) {
        try {
            log.debug("Searching for WebAuthn user by userId: {}", userId);

            if ((this.anonymousUser != null) && (MessageDigest.isEqual(this.anonymousUser.getId().getBytes(), userId.getBytes()))) {
                log.info("Found WebAuthn anonymous user by userId: {}, userEntity: {}", userId, this.prettyJson.pretty(this.anonymousUser));
                return this.anonymousUser;
            }
//            final PublicKeyCredentialUserEntity publicKeyCredentialAnonymousUserEntity = this.anonymousUsers.get(userId.getBytes());
//            if (publicKeyCredentialAnonymousUserEntity != null) {
//                log.info("Found WebAuthn anonymous user by userId: {}, userEntity: {}", userId, this.prettyJson.pretty(publicKeyCredentialAnonymousUserEntity));
//                return publicKeyCredentialAnonymousUserEntity;
//            }

            final PersonOrm personOrm = this.personOrmRepository.findByWebauthnId(userId.getBytes()).orElse(null);
            if (personOrm == null) {
                log.info("No WebAuthn user found by userId: {}", userId);
                return null;
            }
            log.info("Found WebAuthn user by userId: {}, userEntity: {}", userId, this.prettyJson.pretty(personOrm));
            final PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = toPublicKeyCredentialUserEntity(personOrm);
            log.info("Returning WebAuthn user by userId: {}, publicKeyCredentialUserEntity: {}", userId, this.prettyJson.pretty(publicKeyCredentialUserEntity));
            return publicKeyCredentialUserEntity;
        } catch (Exception e) {
            log.error("Error searching for WebAuthn user by userId: {}", userId, e);
            throw e;
        }
    }

    @Transactional
    @Override
    public PublicKeyCredentialUserEntity findByUsername(final String usernameMixedCase) {
        try {
            if (usernameMixedCase.equalsIgnoreCase(ANONYMOUS_USER)) {
                log.info("Found WebAuthn anonymous user by username: {}, userEntity: {}", usernameMixedCase, this.prettyJson.pretty(this.anonymousUser));
                return this.anonymousUser;
            }
            log.debug("Searching for WebAuthn user by username: {}", usernameMixedCase);
            final String usernameLowerCase = usernameMixedCase.toLowerCase();
            final PersonOrm personOrm = this.personOrmRepository.findByUsername(usernameLowerCase).orElse(null);
            if (personOrm == null) {
                log.info("No WebAuthn user found by username: {}", usernameMixedCase);
                return null;
            }
            log.info("Found WebAuthn user by username: {}, userEntity: {}", usernameMixedCase, this.prettyJson.pretty(personOrm));
            final PublicKeyCredentialUserEntity publicKeyCredentialUserEntity = toPublicKeyCredentialUserEntity(personOrm);
            log.info("Returning WebAuthn user by username: {}, publicKeyCredentialUserEntity: {}", usernameMixedCase, this.prettyJson.pretty(publicKeyCredentialUserEntity));
            return publicKeyCredentialUserEntity;
        } catch (Exception e) {
            log.error("Error searching for WebAuthn user by username: {}", usernameMixedCase, e);
            throw e;
        }
    }

    @Transactional
    @Override
    public void save(final PublicKeyCredentialUserEntity publicKeyCredentialUserEntity) {
        try {
            log.debug("Saving WebAuthn user: {}", this.prettyJson.pretty(publicKeyCredentialUserEntity));
            if (publicKeyCredentialUserEntity.getName().equalsIgnoreCase(ANONYMOUS_USER)) {
                log.info("Saved WebAuthn anonymous user, userEntity: {}", this.prettyJson.pretty(this.anonymousUser));
                return;
            }
            final PublicKeyCredentialUserEntity byUserId   = findById(publicKeyCredentialUserEntity.getId());
            final PublicKeyCredentialUserEntity byUsername = findByUsername(publicKeyCredentialUserEntity.getName());

            if ((byUserId != null) && (byUsername != null)) {
                if (!MessageDigest.isEqual(byUserId.getId().getBytes(), byUsername.getId().getBytes())) {
                    log.error("Mismatch: Name and userId {} refer to different WebAuthn users: byId={} byUsername={}",
                        this.prettyJson.pretty(publicKeyCredentialUserEntity), this.prettyJson.pretty(byUserId), this.prettyJson.pretty(byUsername));
                    throw new IllegalArgumentException("Name vs userId refer to different WebAuthn users");
                }
                log.info("WebAuthn user already exists: {}", this.prettyJson.pretty(publicKeyCredentialUserEntity));
            } else if (byUserId != null) {
                log.error("userId={} exists but Name={} does not", this.prettyJson.pretty(publicKeyCredentialUserEntity), this.prettyJson.pretty(byUserId));
                throw new IllegalArgumentException("Name vs userId mismatch, userId exists but Name does not");
            } else if (byUsername != null) {
                log.error("Name={} exists but userId={} does not", this.prettyJson.pretty(publicKeyCredentialUserEntity), this.prettyJson.pretty(byUsername));
                throw new IllegalArgumentException("Name vs userId mismatch, Name exists but userId does not");
            } else {
                log.info("Creating WebAuthn user: {}", this.prettyJson.pretty(publicKeyCredentialUserEntity));
                final PersonOrm savedPersonOrm = this.personOrmRepository.save(
                    PersonOrm.builder()
                             .username(publicKeyCredentialUserEntity.getName())
                             .name(NameOrm.builder().nickname(publicKeyCredentialUserEntity.getDisplayName()).build())
                             .webauthnId(publicKeyCredentialUserEntity.getId().getBytes())
                             .personStatus(PersonStatusType.ACT)
                             .build()
                );
                log.info("Created WebAuthn user: {}", this.prettyJson.pretty(savedPersonOrm));
            }
        } catch (Exception e) {
            log.error("Error saving WebAuthn user: {}", this.prettyJson.pretty(publicKeyCredentialUserEntity), e);
            throw e;
        }
    }

    @Override
    public void delete(final Bytes userId) {
        if ((this.anonymousUser != null) && (MessageDigest.isEqual(this.anonymousUser.getId().getBytes(), userId.getBytes()))) {
            log.info("Delete WebAuthn anonymous user by userId: {}, userEntity: {}", userId, this.prettyJson.pretty(this.anonymousUser));
            return;
        }
        log.warn("Delete operation not supported for userId: {}", userId);
        throw new UnsupportedOperationException("Delete by userId not supported at this time"); // TODO Maybe later?
    }

    private static PublicKeyCredentialUserEntity toPublicKeyCredentialUserEntity(final PersonOrm personOrm) {
        if (personOrm == null) {
            return null;
        }
        return ImmutablePublicKeyCredentialUserEntity.builder()
            .name(personOrm.username())
            .id(new Bytes(personOrm.externalId()))
            .displayName(personOrm.name().nickname())
            .build();
    }
}
