package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Set;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.session.Session;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Entity
@Audited
@Table(name="session")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE session SET pre_delete_date_time=NOW() WHERE id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="session_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_LARGE)
public class SessionOrm extends AbstractEntity implements Session {
	public static final Duration MAX_INACTIVE_INTERNAL = Duration.ofMinutes(15);

	@ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="person_id",nullable=false,updatable=false)
    @NotNull
    private PersonOrm person;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="persona_id",nullable=false,updatable=false)
    @NotNull
    private PersonaOrm persona;

    @Column(updatable=false,nullable=false)
    @Lob
    @NotNull
    private byte[] sessionData;

    @Column(nullable=false)
    @NotNull
    @Builder.Default
	private OffsetDateTime lastAccessedAt = DateTimeUtil.nowUtcTruncatedToMicroseconds();

    @Column(updatable=false,nullable=false)
    @NotNull
    @Builder.Default
	private OffsetDateTime expiresAt = DateTimeUtil.nowUtcTruncatedToMicroseconds().plusMinutes(30L);

    @Column(updatable=false,nullable=false)
    @NotNull
    @Builder.Default
	private Duration maxInactiveInternal = MAX_INACTIVE_INTERNAL;

	@Override
	public String getId() {
		return Base64Util.URL.encodeToString(super.externalId()); // ASSUME: 40-bytes * 4/3 => 54-chars
	}
	@Override
	public String changeSessionId() {
		super.externalId(super.generateSessionId()); // generate new bytes
		return this.getId(); // read new bytes as base64 url-encoded
	}

	@Override
	public Instant getCreationTime() {
		return super.createdDate().toInstant();
	}
	@Override
	public Instant getLastAccessedTime() {
		return this.lastAccessedAt.toInstant();
	}
	@Override
	public void setLastAccessedTime(Instant lastAccessedTime) {
		this.lastAccessedAt = lastAccessedTime.atOffset(ZoneOffset.UTC);
	}

	@Override
	public Duration getMaxInactiveInterval() {
		return this.maxInactiveInternal;
	}
	@Override
	public void setMaxInactiveInterval(Duration interval) {
		this.maxInactiveInternal = interval;
	}

	@Override
	public boolean isExpired() {
		return DateTimeUtil.nowUtcTruncatedToMicroseconds().compareTo(this.expiresAt) >= 0;
	}

	@Override
	public <T> T getAttribute(String attributeName) {
		return null;
	}

	@Override
	public Set<String> getAttributeNames() {
		return null;
	}

	@Override
	public void setAttribute(String attributeName, Object attributeValue) {
	}

	@Override
	public void removeAttribute(String attributeName) {
	}

//    /*package*/ void delete() {
//    	this.persona.deleteSession(this); // cascade delete through persona and person
//	}
}