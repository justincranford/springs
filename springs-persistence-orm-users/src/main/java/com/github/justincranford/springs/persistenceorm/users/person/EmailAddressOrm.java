package com.github.justincranford.springs.persistenceorm.users.person;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.enums.EmailAddressType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
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
@Table(name="email_address",indexes= {@Index(name="idx_unique_persona_rank",columnList="persona_id,rank",unique=true)})
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE email_address SET pre_delete_date_time=NOW() WHERE id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="email_address_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
class EmailAddressOrm extends AbstractEntity {
	@Column(nullable=false)
	private Short rank;

    @Email
    @Column(length=320,nullable=false) // 64+1+255
    @Size(min=3,max=320) // RFC 5321
    @NotNull
    private String emailAddress;

    @Enumerated(EnumType.STRING)
    @Column(name="email_address_type",length=3,nullable=false,columnDefinition="CHAR(3)")
    @Size(min=3,max=3)
    @NotNull
    private EmailAddressType type;

	@ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="persona_id",foreignKey=@ForeignKey(name="fk_email_address_persona_id_2_persona_id"))
    private PersonaOrm persona;

}