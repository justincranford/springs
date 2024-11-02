package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Set;

import org.springframework.session.Session;

import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Builder
public class SessionPojo implements Session {
	@Getter
	@Setter
	private PersonOrm personOrm;

	@Getter
	@Setter
	private PersonaOrm personaOrm;

	@Getter
	@Setter
	private byte[] sessionData;

	@Builder.Default
	private String id = Base64Util.URL.encodeToString(SecureRandomUtil.timeStampBytesAndRandomBytes(8, 32));

	@Builder.Default
	private Instant creationTime = nowInstant();

	@Builder.Default
	private Instant lastAccessedTime = nowInstant();

	@Builder.Default
	private Duration maxInactiveInterval = Constants.MAX_INACTIVE_INTERNAL;

	@Builder.Default
	private LinkedHashMap<String, Object> attributes = new LinkedHashMap<>();

	@Override
	public String getId() {
		this.lastAccessedTime = nowInstant();
		return this.id;
	}

	@Override
	public Instant getCreationTime() {
		this.lastAccessedTime = nowInstant();
		return this.creationTime;
	}

	@Override
	public void setLastAccessedTime(Instant lastAccessedTime) {
		this.lastAccessedTime = lastAccessedTime;
	}

	@Override
	public Instant getLastAccessedTime() {
		this.lastAccessedTime = nowInstant();
		return this.lastAccessedTime;
	}

	@Override
	public void setMaxInactiveInterval(Duration interval) {
		this.lastAccessedTime = nowInstant();
		this.maxInactiveInterval = interval;
	}

	@Override
	public Duration getMaxInactiveInterval() {
		this.lastAccessedTime = nowInstant();
		return this.maxInactiveInterval;
	}

	public synchronized LinkedHashMap<String, Object> getAttributes() {
		this.lastAccessedTime = nowInstant();
		return new LinkedHashMap<>(this.attributes);
	}

	public synchronized void setAttributes(final LinkedHashMap<String, Object> newAttributes) {
		this.lastAccessedTime = nowInstant();
		this.attributes = new LinkedHashMap<>(newAttributes);
	}

	@Override
	public synchronized Set<String> getAttributeNames() {
		this.lastAccessedTime = nowInstant();
		return this.attributes.keySet();
	}

	@SuppressWarnings("unchecked")
	@Override
	public synchronized Object getAttribute(String attributeName) {
		this.lastAccessedTime = nowInstant();
		return this.attributes.get(attributeName);
	}

	@Override
	public synchronized void setAttribute(String attributeName, Object attributeValue) {
		this.lastAccessedTime = nowInstant();
		this.attributes.put(attributeName, attributeValue);
	}

	@Override
	public synchronized void removeAttribute(String attributeName) {
		this.lastAccessedTime = nowInstant();
		this.attributes.remove(attributeName);
	}

	@Override
	public String changeSessionId() {
		this.lastAccessedTime = nowInstant();
		this.id = Base64Util.URL.encodeToString(SecureRandomUtil.timeStampBytesAndRandomBytes(8, 32));
		return this.id;
	}

	@Override
	public boolean isExpired() {
		this.lastAccessedTime = nowInstant();
		return nowInstant().isAfter(this.lastAccessedTime.plus(this.maxInactiveInterval));
	}

	private static Instant nowInstant() {
		return DateTimeUtil.nowUtcTruncatedToMicroseconds().toInstant();
	}

    public static class Constants {
		public static final Duration MAX_INACTIVE_INTERNAL = Duration.ofMinutes(15);
	}
}
