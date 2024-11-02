package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.github.justincranford.springs.util.basic.Base64Util;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Repository
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"nls"})
public class SessionPojoRepository implements SessionRepository<SessionPojo> {
    private final SessionOrmRepository sessionOrmRepository;

    @Override
    public SessionPojo createSession() {
        return SessionPojo.builder().build();
    }

    @Override
    public void save(SessionPojo session) {
        this.sessionOrmRepository.save(SessionPojoRepository.pojoToOrm(session));
    }

    @Override
    public SessionPojo findById(String externalIdBase64Url) {
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
		return this.sessionOrmRepository.findByExternalId(externalIdBytes)
            .map(SessionPojoRepository::ormToPojo)
			.orElse(null);
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

    private static SessionOrm pojoToOrm(SessionPojo sessionPojo) {
    	final AtomicInteger rank = new AtomicInteger(0);
        return SessionOrm.builder()
            .person(sessionPojo.getPersonOrm())
            .persona(sessionPojo.getPersonaOrm())
            .sessionData(sessionPojo.getSessionData())
            .lastAccessedAt(sessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC)) 
            .expiresAt(sessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC).plus(sessionPojo.getMaxInactiveInterval()))
            .maxInactiveInternal(sessionPojo.getMaxInactiveInterval())
            .attributes(
        		sessionPojo.getAttributes().entrySet().stream().collect(
    				Collectors.toMap(
    					Map.Entry::getKey,
    					entry -> new AttributeOrm((short) rank.getAndIncrement(), (String) entry.getValue()),
    			        (existing, replacement) -> existing,
    			        LinkedHashMap::new
    				)
    			)
    		)
            .build();
    }

    private static SessionPojo ormToPojo(SessionOrm sessionOrm) {
		return SessionPojo.builder()
            .personaOrm(sessionOrm.persona())
            .personOrm(sessionOrm.person())
            .sessionData(sessionOrm.sessionData())
            .id(Base64Util.URL.encodeToString(sessionOrm.externalId()))
            .creationTime(sessionOrm.prePersistDateTime().toInstant())
            .lastAccessedTime(sessionOrm.lastAccessedAt().toInstant())
            .maxInactiveInterval(sessionOrm.maxInactiveInternal())
            .attributes(sessionOrm.attributes().keySet().stream()
    		    .collect(Collectors.toMap(
			        attributeName -> attributeName,
			        attributeValue -> attributeValue,
			        (existing, replacement) -> existing,
			        LinkedHashMap::new
			    )))
        .build();
    }
}
