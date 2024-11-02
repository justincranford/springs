package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

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

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OrderBy;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
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
@SQLDelete(sql="UPDATE session SET pre_delete_date_time=NOW() WHERE id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="session_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_LARGE)
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Accessors(fluent=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper=true)
public class SessionOrm extends AbstractEntity implements Session {
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
	private Duration maxInactiveInternal = Constants.MAX_INACTIVE_INTERNAL;

    @ElementCollection
    @CollectionTable(
		name="attribute",
    	joinColumns=@JoinColumn(name="sessionId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name="fk_attribute_session_id"),
		uniqueConstraints={@UniqueConstraint(name="idx_attribute_session_id_rank",columnNames={"session_id","rank"})}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @OrderBy("session_id,rank")
    @NotNull
    @Size(min=0,max=16)
    @Builder.Default
    private List<AttributeOrm> attributes = new ArrayList<>();

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
	public Set<String> getAttributeNames() {
		return this.attributes.stream().map(attributeOrm -> attributeOrm.name()).collect(Collectors.toSet());
	}

	@SuppressWarnings("unchecked")
	@Override
	public String getAttribute(final String attributeName) {
		return this.attributes.stream().filter(attributeOrm -> attributeOrm.name().equals(attributeName)).findFirst().map(attributeOrm -> attributeOrm.value()).map(value -> value.toString()).orElse(null);
	}

	@Override
	public void setAttribute(final String attributeName, final Object attributeValue) {
		this.attributes.stream().filter(attributeOrm -> attributeOrm.name().equals(attributeName)).findFirst().map(attributeOrm -> attributeOrm.value(attributeValue.toString()));
	}

	@Override
	public void removeAttribute(final String attributeName) {
		this.attributes = this.attributes.stream().filter(attributeOrm -> (!(attributeOrm.name().equals(attributeName)))).toList();
	}

    public static class Constants {
		public static final Duration MAX_INACTIVE_INTERNAL = Duration.ofMinutes(15);
	}
}