package com.github.justincranford.springs.persistenceredis.sessions.database.entity;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

import com.github.justincranford.springs.persistenceorm.clients.client.ClientOrm;
import lombok.AccessLevel;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.MapKeyColumn;
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
@SQLDelete(sql="UPDATE session SET pre_delete_date_time=CURRENT_TIMESTAMP WHERE id=? AND version=?")
@SQLRestriction(AbstractEntity.SQL_WHERE_CLAUSE)
@SequenceGenerator(sequenceName="session_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_LARGE)
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Accessors(fluent=true)
@Builder
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper=true)
public class SessionOrm extends AbstractEntity {
	@ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="person_id",updatable=false)
    private PersonOrm person;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="persona_id",updatable=false)
    private PersonaOrm persona;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="client_id",updatable=false)
    private ClientOrm client;

    @Column(nullable=false)
    @NotNull
    @Builder.Default
	private OffsetDateTime lastAccessedAt = DateTimeUtil.nowUtcTruncatedToMicroseconds();

    @Column(nullable=false)
    @NotNull
    @Builder.Default
	private OffsetDateTime expiresAt = DateTimeUtil.nowUtcTruncatedToMicroseconds().plusMinutes(30L);

    @Column(nullable=false)
    @NotNull
    @Builder.Default
	private Duration maxInactiveInterval = Constants.MAX_INACTIVE_INTERNAL;

    @ElementCollection
    @CollectionTable(
		name="session_attribute",
    	joinColumns=@JoinColumn(name="sessionId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name="fk_attribute_session_id"),
		uniqueConstraints={
			@UniqueConstraint(name="idx_attribute_session_id_rank",columnNames={"session_id","rank"}),
			@UniqueConstraint(name="idx_attribute_session_id_name",columnNames={"session_id","name"})
		}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @MapKeyColumn(name="name",nullable=false,updatable=false,length=128)
    @OrderBy("session_id,rank")
    @Column(name="encoded")
    @NotNull
    @Size(min=0,max=16)
    @Builder.Default
    private Map<String, AttributeOrm> attributes = new LinkedHashMap<>();

    @NoArgsConstructor(access=AccessLevel.PRIVATE)
    public static final class Constants {
		public static final Duration MAX_INACTIVE_INTERNAL = Duration.ofMinutes(15);
	}
}
