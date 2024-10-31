package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.Instant;

import org.springframework.security.crypto.codec.Base64;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Repository
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"nls"})
public class SessionRepositoryFacade implements SessionRepository<SessionOrm> {
    private final SessionOrmRepository sessionOrmRepository;

    @Override
    public SessionOrm createSession() {
        return SessionOrm.builder().build();
    }

    @Transactional
    @Override
    public void save(final SessionOrm sessionOrm) {
        this.sessionOrmRepository.save(sessionOrm);
    }

    @Transactional
    @Override
    public SessionOrm findById(final String externalIdBase64Url) {
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
		return this.sessionOrmRepository.findByExternalId(externalIdBytes).orElse(null);
    }

	@Transactional
    @Override
    public void deleteById(final String externalIdBase64Url) {
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
		final Long id = this.sessionOrmRepository.getIdByExternalId(externalIdBytes).orElse(null);
		if (id == null) {
			log.warn("Session not found for externalId: {}", externalIdBase64Url);
		} else {
			log.warn("Session found for externalId: {}", externalIdBase64Url);
	        this.sessionOrmRepository.deleteById(id);
		}
    }
}