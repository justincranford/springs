package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;

import org.springframework.session.MapSession;
import org.springframework.session.Session;

import com.github.justincranford.springs.persistenceorm.base.entity.ExternalIdUtil;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

@AllArgsConstructor
@Builder
@ToString
public class SessionPojo implements Session {
	@Getter
	@Setter
	private PersonOrm person;

	@Getter
	@Setter
	private PersonaOrm persona;

	@Builder.Default
	private List<String> replacedIds = new ArrayList<>(0);

	@Builder.Default
	private String id = Base64Util.URL.encodeToString(ExternalIdUtil.generate());

	@Builder.Default
	private Instant creationTime = nowInstant();

	@Builder.Default
	private Instant lastAccessedTime = nowInstant();

	@Builder.Default
	private Duration maxInactiveInterval = Constants.MAX_INACTIVE_INTERNAL;

	private Instant expiresTime;

	@Builder.Default
	private LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();

	public List<String> getReplacedIds() {
		return this.replacedIds;
	}

	@Override
	public String getId() {
//		this.lastAccessedTime = nowInstant();
		return this.id;
	}

	@Override
	public Instant getCreationTime() {
//		this.lastAccessedTime = nowInstant();
		return this.creationTime;
	}

	@Override
	public void setLastAccessedTime(Instant _lastAccessedTime) {
		this.lastAccessedTime = _lastAccessedTime;
    	if (this.maxInactiveInterval.isPositive()) {
        	this.expiresTime = this.lastAccessedTime.plus(this.maxInactiveInterval);
    	} else {
        	this.expiresTime = DateTimeUtil.nowUtcTruncatedToMicroseconds().plusYears(100).toInstant();
    	}
	}

	@Override
	public Instant getLastAccessedTime() {
//		this.lastAccessedTime = nowInstant();
		return this.lastAccessedTime;
	}

	@Override
	public void setMaxInactiveInterval(Duration _maxInactiveInterval) {
//		this.lastAccessedTime = nowInstant();
		this.maxInactiveInterval = _maxInactiveInterval;
    	if (this.maxInactiveInterval.isPositive()) {
        	this.expiresTime = this.lastAccessedTime.plus(this.maxInactiveInterval);
    	} else {
        	this.expiresTime = DateTimeUtil.nowUtcTruncatedToMicroseconds().plusYears(100).toInstant();
    	}
	}

	@Override
	public Duration getMaxInactiveInterval() {
//		this.lastAccessedTime = nowInstant();
		return this.maxInactiveInterval;
	}

	public void setExpiresTime(Instant _expiresTime) {
//		this.lastAccessedTime = nowInstant();
		this.expiresTime = _expiresTime;
	}

	public Instant getExpiresTime() {
//		this.lastAccessedTime = nowInstant();
		return this.expiresTime;
	}

	public synchronized LinkedHashMap<String, Object> getAttributes() {
//		this.lastAccessedTime = nowInstant();
		return new LinkedHashMap<>(this.attributes);
	}

	public synchronized void setAttributes(final LinkedHashMap<String, Object> _attributes) {
//		this.lastAccessedTime = nowInstant();
		this.attributes = new LinkedHashMap<>(_attributes);
	}

	@Override
	public synchronized Set<String> getAttributeNames() {
//		this.lastAccessedTime = nowInstant();
		return this.attributes.keySet();
	}

	@SuppressWarnings("unchecked")
	@Override
	public synchronized Object getAttribute(String attributeName) {
//		this.lastAccessedTime = nowInstant();
		return this.attributes.get(attributeName);
	}

	@Override
	public synchronized void setAttribute(String attributeName, Object attributeValue) {
//		this.lastAccessedTime = nowInstant();
		if (attributeValue == null) {
			this.attributes.remove(attributeName);
		} else {
			this.attributes.put(attributeName, attributeValue);
		}
	}

	@Override
	public synchronized void removeAttribute(String attributeName) {
//		this.lastAccessedTime = nowInstant();
		this.attributes.remove(attributeName);
	}

	@Override
	public String changeSessionId() {
//		this.lastAccessedTime = nowInstant();
		this.replacedIds.add(this.id);
		this.id = Base64Util.URL.encodeToString(ExternalIdUtil.generate());
		return this.id;
	}

	@Override
	public boolean isExpired() {
//		this.lastAccessedTime = nowInstant();
		return nowInstant().isAfter(this.lastAccessedTime.plus(this.maxInactiveInterval));
	}

	private static Instant nowInstant() {
		return DateTimeUtil.nowUtcTruncatedToMicroseconds().toInstant();
	}

    public static class Constants {
		public static final Duration MAX_INACTIVE_INTERNAL = MapSession.DEFAULT_MAX_INACTIVE_INTERVAL;
	}
}
