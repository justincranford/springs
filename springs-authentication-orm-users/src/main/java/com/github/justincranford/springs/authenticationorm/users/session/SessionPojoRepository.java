package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.session.SessionRepository;
import org.springframework.stereotype.Repository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.json.config.PrettyJson;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Repository
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"nls"})
public class SessionPojoRepository implements org.springframework.session.SessionRepository<SessionPojo> {
	@Autowired
    private SessionOrmRepository sessionOrmRepository;
	@Autowired
    private ObjectMapper objectMapper;
	@Autowired
    private PrettyJson prettyJson;

	public List<SessionOrm> cleanUpExpiredSessions() {
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
		final List<SessionOrm> sessionOrms = this.sessionOrmRepository.findAll();
		final List<SessionOrm> cleanedSessionOrms = new ArrayList<>();
		for (SessionOrm sessionOrm : sessionOrms) {
			final Instant lastAccessedAt = sessionOrm.lastAccessedAt().toInstant();
			final Duration maxInactiveInternal = sessionOrm.maxInactiveInternal();
			final Instant expiresAt = lastAccessedAt.plus(maxInactiveInternal);
			final Instant nowInstant = DateTimeUtil.nowUtcTruncatedToMicroseconds().toInstant();
			log.info("\nnowInstant:     {}, \nexpiresAt:      {}, \nlastAccessedAt: {}, \nmaxInactiveInternal: {}", nowInstant, expiresAt, lastAccessedAt, maxInactiveInternal);
			if (expiresAt.isBefore(nowInstant)) {
				this.sessionOrmRepository.delete(sessionOrm);
				cleanedSessionOrms.add(sessionOrm);
			}
		}
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
		return cleanedSessionOrms;
	}

	public Map<String, SessionPojo> findByIndexNameAndIndexValue(final String name, final Object value) {
		return Map.of();
	}

	@Override
    public SessionPojo createSession() {
        final SessionPojo sessionPojo = SessionPojo.builder().build();
        sessionPojo.setExpiresTime(sessionPojo.getCreationTime().plus(sessionPojo.getMaxInactiveInterval()));
		return sessionPojo;
    }

    @Override
    public void save(SessionPojo sessionPojo) {
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(sessionPojo.getId());
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllByExternalIdIncludingDeleted(externalIdBytes));
		final Optional<SessionOrm> sessionOrms = this.sessionOrmRepository.findByExternalIdIncludingDeleted(externalIdBytes);
		this.prettyJson.logAndSave(sessionOrms);
		final SessionOrm sessionOrm;
		if (sessionOrms.isEmpty()) { // INSERT
			sessionOrm = this.pojoToOrm(sessionPojo);
		} else { // UPDATE
			sessionOrm = sessionOrms.get();
			sessionOrm.lastAccessedAt(sessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC));
			sessionOrm.maxInactiveInternal(sessionPojo.getMaxInactiveInterval());
			sessionOrm.expiresAt(sessionPojo.getExpiresTime().atOffset(ZoneOffset.UTC));
			sessionOrm.attributes(pojoToOrm(sessionPojo.getAttributes()));
		}
		this.sessionOrmRepository.save(sessionOrm);
    }

    @Override
    public SessionPojo findById(String externalIdBase64Url) {
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
//            .person(sessionPojo.getPerson())
//            .persona(sessionPojo.getPersona())
//            .sessionData(sessionPojo.getSessionData())
            .lastAccessedAt(sessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC)) 
            .maxInactiveInternal(sessionPojo.getMaxInactiveInterval())
            .expiresAt(sessionPojo.getExpiresTime().atOffset(ZoneOffset.UTC))
            .attributes(this.pojoToOrm(sessionPojo.getAttributes()))
            .build();
        sessionOrm.externalId(Base64Util.URL.decodeFromString(sessionPojo.getId()));
        return sessionOrm;
    }

    private SessionPojo ormToPojo(SessionOrm sessionOrm) {
		return SessionPojo.builder()
//            .persona(sessionOrm.persona())
//            .person(sessionOrm.person())
//            .sessionData(sessionOrm.sessionData())
            .id(Base64Util.URL.encodeToString(sessionOrm.externalId()))
            .creationTime(sessionOrm.prePersistDateTime().toInstant())
            .lastAccessedTime(sessionOrm.lastAccessedAt().toInstant())
            .expiresTime(sessionOrm.expiresAt().toInstant())
            .maxInactiveInterval(sessionOrm.maxInactiveInternal())
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
        			return this.objectMapper.readValue(entry.getValue().encoded(), Object.class);
        		} catch (JsonProcessingException e) {
        			throw new RuntimeException(e);
        		}
            },
            (oldValue, newValue) -> oldValue,
            LinkedHashMap::new
        ));
	}
}
