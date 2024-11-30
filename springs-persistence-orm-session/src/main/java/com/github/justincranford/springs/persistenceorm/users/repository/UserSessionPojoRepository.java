package com.github.justincranford.springs.persistenceorm.users.repository;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.users.model.UserSessionPojo;
import com.github.justincranford.springs.persistenceredis.sessions.database.entity.AttributeOrm;
import com.github.justincranford.springs.persistenceredis.sessions.database.entity.SessionOrm;
import com.github.justincranford.springs.persistenceredis.sessions.database.repository.SessionOrmRepository;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.json.PrettyJson;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Repository;

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

@Repository
@Primary
@RequiredArgsConstructor
@Slf4j
public class UserSessionPojoRepository implements FindByIndexNameSessionRepository<UserSessionPojo> {
	private static final String SPRING_SECURITY_CONTEXT = "SPRING_SECURITY_CONTEXT";

	@Autowired
    private SessionOrmRepository sessionOrmRepository;
	@Autowired
    private ObjectMapper objectMapper;
	@Autowired
    private PrettyJson prettyJson;

	public List<SessionOrm> cleanUpExpiredSessions() {
		log.info("Cleaning up expired sessions");
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
//		final List<SessionOrm> sessionOrms = this.sessionOrmRepository.findAllExpired(DateTimeUtil.nowUtcTruncatedToMicroseconds());
		final List<SessionOrm> sessionOrms = this.sessionOrmRepository.findAll();
//		this.prettyJson.logAndSave(sessionOrms);
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
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
		return cleanedSessionOrms;
	}

	@Override
	public Map<String,UserSessionPojo> findByIndexNameAndIndexValue(final String name, final String value) {
		log.info("Finding by index name [{}] and index value [{}]", name, value);
		if (!PRINCIPAL_NAME_INDEX_NAME.equals(name)) {
			return Collections.emptyMap();
		}
		final List<SessionOrm> sessionOrms = this.sessionOrmRepository.findAll();
		final Map<String,UserSessionPojo> sessionMap = new HashMap<>();
		for (SessionOrm sessionOrm : sessionOrms) {
			final UserSessionPojo userSessionPojo = ormToPojo(sessionOrm);
			final Object principalNameAttribute = userSessionPojo.getAttribute(PRINCIPAL_NAME_INDEX_NAME);
			if ((principalNameAttribute instanceof String principalName) && (principalName.equals(value))) {
				sessionMap.put(userSessionPojo.getId(), userSessionPojo);
			}
			final Object springSecurityContextAttribute = userSessionPojo.getAttribute(SPRING_SECURITY_CONTEXT);
			if (springSecurityContextAttribute instanceof SecurityContext springSecurityContext) {
				final Authentication authentication = springSecurityContext.getAuthentication();
				final String name2 = authentication.getName();
				if (name2.equals(value)) {
					sessionMap.put(userSessionPojo.getId(), userSessionPojo);
				}
			}
			if (springSecurityContextAttribute instanceof SecurityContext springSecurityContext) {
				final Authentication authentication = springSecurityContext.getAuthentication();
				final String name2 = authentication.getName();
				if (name2.equals(value)) {
					sessionMap.put(userSessionPojo.getId(), userSessionPojo);
				}
			}
			if (springSecurityContextAttribute instanceof LinkedHashMap springSecurityContext) {
				final Object authentication = springSecurityContext.get("authentication");
				if (authentication instanceof LinkedHashMap authenticationAttributes) {
					final Object nameAttribute = authenticationAttributes.get("name");
					if (nameAttribute instanceof String) {
						if (nameAttribute.equals(value)) {
							sessionMap.put(userSessionPojo.getId(), userSessionPojo);
						}
					}
				}
			}
		}
		return sessionMap;
	}

	@Override
    public UserSessionPojo createSession() {
		log.info("Create session");
        final UserSessionPojo userSessionPojo = UserSessionPojo.builder().build();
        if (userSessionPojo.getMaxInactiveInterval().isPositive()) {
            userSessionPojo.setExpiresTime(userSessionPojo.getCreationTime().plus(userSessionPojo.getMaxInactiveInterval()));
        } else {
            userSessionPojo.setExpiresTime(DateTimeUtil.nowUtcTruncatedToMicroseconds().plusYears(100).toInstant());
        }
		return userSessionPojo;
    }

    @Override
    public void save(UserSessionPojo userSessionPojo) {
		log.info("Save session, pojo:\n{}", this.prettyJson.pretty(userSessionPojo));
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(userSessionPojo.getId());
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllByExternalIdIncludingDeleted(externalIdBytes));

		if (!userSessionPojo.getReplacedIds().isEmpty()) {
			log.info("Deleting replaced IDs");
			for (final String oldId : userSessionPojo.getReplacedIds()) {
				log.info("Finding ID {}", oldId);
		        final byte[] oldExternalIdBytes = Base64Util.URL.decodeFromString(oldId);
				final Optional<SessionOrm> optionalSessionOrm = this.sessionOrmRepository.findByExternalIdIncludingDeleted(oldExternalIdBytes);
				this.prettyJson.logAndSave(optionalSessionOrm);
				if (optionalSessionOrm.isPresent()) { // DELETE
					log.info("Deleting ID {}", oldId);
					this.sessionOrmRepository.delete(optionalSessionOrm.get());
				}
			}
		}
		final Optional<SessionOrm> optionalSessionOrm = this.sessionOrmRepository.findByExternalIdIncludingDeleted(externalIdBytes);
		this.prettyJson.logAndSave(optionalSessionOrm);
		final SessionOrm sessionOrm;
		if (optionalSessionOrm.isEmpty()) { // INSERT
			sessionOrm = this.pojoToOrm(userSessionPojo);
			log.info("Inserting session, orm:\n{}", this.prettyJson.pretty(sessionOrm));
		} else { // UPDATE
			sessionOrm = optionalSessionOrm.get();
			sessionOrm.lastAccessedAt(userSessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC));
			sessionOrm.maxInactiveInterval(userSessionPojo.getMaxInactiveInterval());
			sessionOrm.expiresAt(userSessionPojo.getExpiresTime().atOffset(ZoneOffset.UTC));
			sessionOrm.attributes(pojoToOrm(userSessionPojo.getAttributes()));
			log.info("Updating session, orm:\n{}", this.prettyJson.pretty(sessionOrm));
		}
		this.sessionOrmRepository.save(sessionOrm);
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
    }

    @Override
    public UserSessionPojo findById(String externalIdBase64Url) {
		log.info("Finding by ID: {}", externalIdBase64Url);
    	// TODO Cleanup expired sessions
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
		final UserSessionPojo userSessionPojo = this.sessionOrmRepository.findByExternalId(externalIdBytes)
																		 .map(this::ormToPojo)
																		 .orElse(null);
		log.info("Found by ID: {}", this.prettyJson.pretty(userSessionPojo));
		return userSessionPojo;
    }

    @Override
    public void deleteById(final String externalIdBase64Url) {
		log.info("Deleting by ID: {}", externalIdBase64Url);
        final byte[] externalIdBytes = Base64Util.URL.decodeFromString(externalIdBase64Url);
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
		this.prettyJson.logAndSave(this.sessionOrmRepository.findAllByExternalIdIncludingDeleted(externalIdBytes));
		final Optional<Long> optionalSessionOrmId = this.sessionOrmRepository.findIdByExternalIdIncludingDeleted(externalIdBytes);
		this.prettyJson.logAndSave(optionalSessionOrmId);
		if (optionalSessionOrmId.isEmpty()) {
			log.warn("Session ID not found for externalId: {}", externalIdBase64Url);
		} else {
			final Long id = optionalSessionOrmId.get();
			log.warn("Session ID {} found for externalId: {}", id, externalIdBase64Url);
	        this.sessionOrmRepository.deleteById(id);
//			this.prettyJson.logAndSave(this.sessionOrmRepository.findAllIncludingDeleted());
//			this.prettyJson.logAndSave(this.sessionOrmRepository.findAllByExternalIdIncludingDeleted(externalIdBytes));
		}
//		this.prettyJson.logAndSave(this.sessionOrmRepository.findAll());
    }

    public List<UserSessionPojo> findAll() {
        final List<SessionOrm> findAll = this.sessionOrmRepository.findAll();
//        this.prettyJson.log(findAll);
		return findAll.stream().map(this::ormToPojo).toList();
    }

    private SessionOrm pojoToOrm(UserSessionPojo userSessionPojo) {
        final SessionOrm sessionOrm = SessionOrm.builder()
            .person(userSessionPojo.getPerson())
            .persona(userSessionPojo.getPersona())
            .lastAccessedAt(userSessionPojo.getLastAccessedTime().atOffset(ZoneOffset.UTC))
            .maxInactiveInterval(userSessionPojo.getMaxInactiveInterval())
            .expiresAt(userSessionPojo.getExpiresTime().atOffset(ZoneOffset.UTC))
            .attributes(this.pojoToOrm(userSessionPojo.getAttributes()))
            .build();
        sessionOrm.externalId(Base64Util.URL.decodeFromString(userSessionPojo.getId()));
        return sessionOrm;
    }

    private UserSessionPojo ormToPojo(SessionOrm sessionOrm) {
		return UserSessionPojo.builder()
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
					assert value != null;
					final String encoded = value.encoded();
					assert encoded != null;
	                return switch (entry.getKey()) {
	                    case "SPRING_SECURITY_CONTEXT"            -> this.objectMapper.readValue(encoded, SecurityContextImpl.class);
	                    case "SPRING_SECURITY_SAVED_REQUEST"      -> this.objectMapper.readValue(encoded, SavedRequest.class);
	                    case "SPRING_SECURITY_LAST_EXCEPTION"     -> this.objectMapper.readValue(encoded, AuthenticationException.class);
	                    case "SPRING_SECURITY_FILTER_CHAIN"       -> this.objectMapper.readValue(encoded, FilterChainProxy.class);
	                    case "SPRING_SECURITY_REAUTHENTICATE"     -> Boolean.parseBoolean(encoded);
	                    case "SPRING_SECURITY_REMEMBER_ME_COOKIE" -> encoded;
	                    default                                   -> this.objectMapper.readValue(encoded, Object.class);
	                };
        		} catch (JsonProcessingException e) {
        			throw new RuntimeException(e);
        		}
            },
            (oldValue, newValue) -> oldValue,
            LinkedHashMap::new
        ));
	}
}
