package com.github.justincranford.springs.authenticationorm.users.session;

import java.time.OffsetDateTime;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrm;
import com.github.justincranford.springs.persistenceorm.users.person.PersonaOrm;
import com.github.justincranford.springs.util.basic.DateTimeUtil;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.JoinColumn;
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
public class SessionOrm extends AbstractEntity {
    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="person_id",nullable=false,updatable=false)
    @NotNull
    private PersonOrm person;

    @ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="persona_id",nullable=false,updatable=false)
    @NotNull
    private PersonaOrm persona;

    @Column(updatable=false,nullable=false)
    @NotNull
    @Builder.Default
	private OffsetDateTime expiresAt = DateTimeUtil.nowUtcTruncatedToMicroseconds().plusMinutes(30L);

//    /*package*/ void delete() {
//    	this.persona.deleteSession(this); // cascade delete through persona and person
//	}
}