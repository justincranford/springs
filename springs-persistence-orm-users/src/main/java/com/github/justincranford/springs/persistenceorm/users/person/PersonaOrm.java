package com.github.justincranford.springs.persistenceorm.users.person;

import java.util.List;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonaType;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Entity
@Audited
@Table(name="persona")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE persona SET pre_delete_date_time=NOW() WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="persona_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
public class PersonaOrm extends AbstractEntity {
    @ElementCollection
    @CollectionTable(name="email_addresses")
    @NotNull
    private List<Email> emailAddresses;

    @ElementCollection
    @CollectionTable(name="phone_numbers")
    @NotNull
    private List<Phone> phoneNumbers;

    @ElementCollection
    @CollectionTable(name="addresses")
    @NotNull
    private List<Address> addresses;

    @ElementCollection
    @CollectionTable(name="urls")
    @Null
    private List<URL> urls;

    @Enumerated(EnumType.STRING)
    @NotNull
    private PersonaType personaType;

	@ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="person_id",foreignKey=@ForeignKey(name="fk_persona_personid_2_person_id"))
    private PersonOrm person;
}