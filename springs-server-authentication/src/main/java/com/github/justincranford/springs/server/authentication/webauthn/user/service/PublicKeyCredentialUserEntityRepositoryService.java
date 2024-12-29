package com.github.justincranford.springs.server.authentication.webauthn.user.service;

import com.github.justincranford.springs.persistenceorm.users.person.NameOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonStatusType;
import com.github.justincranford.springs.persistenceorm.users.person.service.PersonService;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.NotSupportedException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class PublicKeyCredentialUserEntityRepositoryService implements PublicKeyCredentialUserEntityRepository {
    @Autowired
    private PersonOrmRepository personOrmRepository;

    @Autowired
    private PersonService personService;

    @Transactional
    @Override
    public PublicKeyCredentialUserEntity findById(final Bytes id) {
        return toPublicKeyCredentialUserEntity(this.personOrmRepository.findByWebauthnId(id.getBytes()).orElse(null));
    }

    @Transactional
    @Override
    public PublicKeyCredentialUserEntity findByUsername(final String username) {
        return toPublicKeyCredentialUserEntity(this.personService.loadPersonByUsername(username));
    }

    @Transactional
    @Override
    public void save(final PublicKeyCredentialUserEntity userEntity) {
        final PersonOrm byUsername   = this.personService.loadPersonByUsername(userEntity.getName().toLowerCase());
        final PersonOrm byExternalId = this.personOrmRepository.findByWebauthnId(userEntity.getId().getBytes()).orElse(null);
        if ((byUsername != null) && (byExternalId != null)) {
            if (byUsername.internalId().longValue() != byExternalId.internalId().longValue()) {
                log.error("Name={} vs ID={} mismatch, they refer to two different people: {} {}", userEntity.getName(), userEntity.getId().getBytes(), byUsername.internalId(), byExternalId.internalId());
                throw new IllegalArgumentException("Name vs ID mismatch, they refer to two different people");
            }
            log.info("Person already exists with that name and externalId");
        } else if (byUsername != null) {
            log.error("Name={} vs ID={} mismatch, name exists but ID does not: {}", userEntity.getName(), userEntity.getId().getBytes(), byUsername.internalId());
            throw new IllegalArgumentException("Name vs ID mismatch, name exists but ID does not");
        } else if (byExternalId != null) {
            log.error("Name={} vs ID={} mismatch, ID exists but Name does not: {}", userEntity.getName(), userEntity.getId().getBytes(), byExternalId.internalId());
            throw new IllegalArgumentException("Name vs ID mismatch, ID exists but Name does not");
        } else {
            log.info("Name={} and ID={} don't exist, creating person now", userEntity.getName(), userEntity.getId().getBytes());
            final PersonOrm savedPersonOrm = this.personOrmRepository.save(
                PersonOrm.builder()
                    .username(userEntity.getName())
                    .name(
                        NameOrm.builder().first(userEntity.getDisplayName()).build()
                    )
                    .webauthnId(userEntity.getId().getBytes())
                    .personStatus(PersonStatusType.ACT)
                    .build()
            );
        }
    }

    @Override
    public void delete(final Bytes id) {
        throw new NotSupportedException("Delete by ID not supported at this time"); // TODO Maybe later?
    }

    private static PublicKeyCredentialUserEntity toPublicKeyCredentialUserEntity(final PersonOrm personOrm) {
        if (personOrm == null) {
            return null;
        }
        return ImmutablePublicKeyCredentialUserEntity.builder()
            .name(personOrm.username())
            .id(new Bytes(personOrm.externalId()))
            .displayName(personOrm.name().first())
            .build();
    }
}
