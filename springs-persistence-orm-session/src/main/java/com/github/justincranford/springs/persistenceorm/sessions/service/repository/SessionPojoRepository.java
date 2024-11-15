package com.github.justincranford.springs.persistenceorm.sessions.service.repository;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Repository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.sessions.database.entity.AttributeOrm;
import com.github.justincranford.springs.persistenceorm.sessions.database.entity.SessionOrm;
import com.github.justincranford.springs.persistenceorm.sessions.database.repository.SessionOrmRepository;
import com.github.justincranford.springs.persistenceorm.sessions.service.model.SessionPojo;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.json.config.PrettyJson;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Repository
@RequiredArgsConstructor
@Slf4j
public class SessionPojoRepository implements FindByIndexNameSessionRepository<SessionPojo> {
	private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

	@Autowired
    private SessionOrmRepository sessionOrmRepository;
	@Autowired
    private ObjectMapper objectMapper;
	@Autowired
    private PrettyJson prettyJson;

	public List<SessionOrm> cleanUpExpiredSessions() {
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
//		final List<SessionOrm> sessionOrms = this.sessionOrmRepository.findAllExpired(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		final List<SessionOrm> sessionOrms = this.sessionOrmRepository.findAll();
		this.prettyJson.logAndSave(sessionOrms);
		final List<SessionOrm> cleanedSessionOrms = new ArrayList<>();
		for (SessionOrm sessionOrm : sessionOrms) {
			final Instant expiresAt = sessionOrm.expiresAt().toInstant();
			final Instant nowInstant = DateTimeUtil.nowUtcTruncatedToMicroseconds().toInstant();
			final Instant lastAccessedAt = sessionOrm.lastAccessedAt().toInstant();
			final Duration maxInactiveInterval = sessionOrm.maxInactiveInterval();
			log.info("\nnowInstant:     {}, \nexpiresAt:      {}, \nlastAccessedAt: {}, \nmaxInactiveInterval: {}", nowInstant, expiresAt, lastAccessedAt, maxInactiveInterval);
			if (expiresAt.isBefore(nowInstant)) {
				this.sessionOrmRepository.delete(sessionOrm);
				cleanedSessionOrms.add(sessionOrm);
			}
		}
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
		return cleanedSessionOrms;
	}

	@Override
	public Map<String, SessionPojo> findByIndexNameAndIndexValue(final String name, final String value) {
		if (!PRINCIPAL_NAME_INDEX_NAME.equals(name)) {
			return Collections.emptyMap();
		}
		final List<SessionOrm> sessionOrms = this.sessionOrmRepository.findAll();
		final Map<String, SessionPojo> sessionMap = new HashMap<>();
		for (SessionOrm sessionOrm : sessionOrms) {
			final SessionPojo sessionPojo = ormToPojo(sessionOrm);
			final Object principalNameAttribute = sessionPojo.getAttribute(PRINCIPAL_NAME_INDEX_NAME);
			if ((principalNameAttribute instanceof String principalName) && (principalName.equals(value))) {
				sessionMap.put(sessionPojo.getId(), sessionPojo);
			}
			final Object springSecurityContextAttribute = sessionPojo.getAttribute(SPRING_SECURITY_CONTEXT);
			if (springSecurityContextAttribute instanceof SecurityContext springSecurityContext) {
				final Authentication authentication = springSecurityContext.getAuthentication();
				final String name2 = authentication.getName();
				if (name2.equals(value)) {
					sessionMap.put(sessionPojo.getId(), sessionPojo);
				}
			}
			if (springSecurityContextAttribute instanceof SecurityContext springSecurityContext) {
				final Authentication authentication = springSecurityContext.getAuthentication();
				final String name2 = authentication.getName();
				if (name2.equals(value)) {
					sessionMap.put(sessionPojo.getId(), sessionPojo);
				}
			}
			if (springSecurityContextAttribute instanceof LinkedHashMap springSecurityContext) {
				final Object authentication = springSecurityContext.get("authentication");
				if (authentication instanceof LinkedHashMap authenticationAttributes) {
					final Object nameAttribute = authenticationAttributes.get("name");
					if (nameAttribute instanceof String) {
						if (nameAttribute.equals(value)) {
							sessionMap.put(sessionPojo.getId(), sessionPojo);
						}
					}
				}
			}
		}
		return sessionMap;
	}

	@Override
    public SessionPojo createSession() {
        final SessionPojo sessionPojo = SessionPojo.builder().build();
        if (sessionPojo.getMaxInactiveInterval().isPositive()) {
            sessionPojo.setExpiresTime(sessionPojo.getCreationTime().plus(sessionPojo.getMaxInactiveInterval()));
        } else {
            sessionPojo.setExpiresTime(DateTimeUtil.nowUtcTruncatedToMicroseconds().plusYears(100).toInstant());
        }
		return sessionPojo;
    }

    @Override
    public void save(SessionPojo sessionPojo) {
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(sessionPojo.getId());
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllByExternalIdIncludingDeleted(externalIdBytes));

		if (sessionPojo.getReplacedIds().size() > 0) {
			for (final String oldId : sessionPojo.getReplacedIds()) {
		        final byte[] oldExternalIdBytes = Base64Util.URL.decodeFromString(oldId);
				final Optional<SessionOrm> optionalSessionOrm = this.sessionOrmRepository.findByExternalIdIncludingDeleted(oldExternalIdBytes);
				this.prettyJson.logAndSave(optionalSessionOrm);
				if (optionalSessionOrm.isPresent()) { // DELETE
					this.sessionOrmRepository.delete(optionalSessionOrm.get());
				}
			}
		}
		final Optional<SessionOrm> optionalSessionOrm = this.sessionOrmRepository.findByExternalIdIncludingDeleted(externalIdBytes);
		this.prettyJson.logAndSave(optionalSessionOrm);
		final SessionOrm sessionOrm;
		if (optionalSessionOrm.isEmpty()) { // INSERT
			sessionOrm = this.pojoToOrm(sessionPojo);
		} else { // UPDATE
			sessionOrm = optionalSessionOrm.get();
			sessionOrm.lastAccessedAt(sessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC));
			sessionOrm.maxInactiveInterval(sessionPojo.getMaxInactiveInterval());
			sessionOrm.expiresAt(sessionPojo.getExpiresTime().atOffset(ZoneOffset.UTC));
			sessionOrm.attributes(pojoToOrm(sessionPojo.getAttributes()));
		}
		this.sessionOrmRepository.save(sessionOrm);
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
    }

    @Override
    public SessionPojo findById(String externalIdBase64Url) {
    	// TODO Cleanup expired sessions
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
		return this.sessionOrmRepository.findByExternalId(externalIdBytes)
            .map(this::ormToPojo)
			.orElse(null);
    }

    @Override
    public void deleteById(final String externalIdBase64Url) {
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllByExternalIdIncludingDeleted(externalIdBytes));
		final Optional<Long> optionalSessionOrmId = this.sessionOrmRepository.findIdByExternalIdIncludingDeleted(externalIdBytes);
		this.prettyJson.logAndSave(optionalSessionOrmId);
		if (optionalSessionOrmId.isEmpty()) {
			log.warn("Session ID not found for externalId: {}", externalIdBase64Url);
		} else {
			final Long id = optionalSessionOrmId.get();
			log.warn("Session ID {} found for externalId: {}", id, externalIdBase64Url);
	        this.sessionOrmRepository.deleteById(id);
			this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
			this.prettyJson.logAndSave(this.sessionOrmRepository.findAllByExternalIdIncludingDeleted(externalIdBytes));
		}
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
    }

    public List<SessionPojo> findAll() {
        final List<SessionOrm> findAll = this.sessionOrmRepository.findAll();
        this.prettyJson.log(findAll);
		return findAll.stream().map(this::ormToPojo).toList();
    }

    private SessionOrm pojoToOrm(SessionPojo sessionPojo) {
        final SessionOrm sessionOrm = SessionOrm.builder()
            .person(sessionPojo.getPerson())
            .persona(sessionPojo.getPersona())
            .lastAccessedAt(sessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC)) 
            .maxInactiveInterval(sessionPojo.getMaxInactiveInterval())
            .expiresAt(sessionPojo.getExpiresTime().atOffset(ZoneOffset.UTC))
            .attributes(this.pojoToOrm(sessionPojo.getAttributes()))
            .build();
        sessionOrm.externalId(Base64Util.URL.decodeFromString(sessionPojo.getId()));
        return sessionOrm;
    }

    private SessionPojo ormToPojo(SessionOrm sessionOrm) {
		return SessionPojo.builder()
            .persona(sessionOrm.persona())
            .person(sessionOrm.person())
            .id(Base64Util.URL.encodeToString(sessionOrm.externalId()))
            .creationTime(sessionOrm.prePersistDateTime().toInstant())
            .lastAccessedTime(sessionOrm.lastAccessedAt().toInstant())
            .expiresTime(sessionOrm.expiresAt().toInstant())
            .maxInactiveInterval(sessionOrm.maxInactiveInterval())
            .attributes(this.ormToPojo(sessionOrm.attributes()))
        .build();
    }

	private LinkedHashMap<String, AttributeOrm> pojoToOrm(LinkedHashMap<String, Object> attributes) {
    	final AtomicInteger rank = new AtomicInteger(0);
		return attributes.entrySet().stream().collect(Collectors.toMap(
			Map.Entry::getKey,
			entry -> new AttributeOrm((short) rank.getAndIncrement(), this.prettyJson.pretty(entry.getValue())),
	        (existing, replacement) -> existing,
	        LinkedHashMap::new
		));
	}

	private LinkedHashMap<String, Object> ormToPojo(final Map<String, AttributeOrm> attributes) {
		return attributes.entrySet().stream().collect(Collectors.toMap(
            Map.Entry::getKey,
            entry -> {
        		try {
        			final AttributeOrm value = entry.getValue();
        			if (value == null) {
        				return null;
        			}
					final String encoded = value.encoded();
					return (encoded == null) ? null : this.objectMapper.readValue(encoded, Object.class);
        		} catch (JsonProcessingException e) {
        			throw new RuntimeException(e);
        		}
            },
            (oldValue, newValue) -> oldValue,
            LinkedHashMap::new
        ));
	}
}
