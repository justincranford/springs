package com.github.justincranford.springs.persistenceorm.users.person;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonaType;

import jakarta.persistence.CascadeType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Null;
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
@Table(name="persona")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE persona SET pre_delete_date_time=NOW() WHERE id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="persona_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
public class PersonaOrm extends AbstractEntity {
    @OneToMany(mappedBy="persona",cascade=CascadeType.ALL,orphanRemoval=true,fetch=FetchType.LAZY)
    @Size(min=1,max=5)
    @OrderBy("rank")
	@NotNull
    @Builder.Default
    private List<@NotNull EmailAddressOrm> emailAddresses = new ArrayList<>();

    @ElementCollection
    @CollectionTable(
		name="phone_numbers",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name = "fk_persona_id"),
    	indexes= {@Index(name="idx_phone_numbers_persona_id_rank",columnList="persona_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(min=1,max=5)
    @Builder.Default
    private List<@NotNull PhoneNumber> phoneNumbers = new ArrayList<>();

    @ElementCollection
    @CollectionTable(
		name="location_addresses",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name = "fk_persona_id"),
    	indexes= {@Index(name="idx_location_addresses_persona_id_rank",columnList="persona_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(min=1,max=4)
    @Builder.Default
    private List<@NotNull LocationAddress> locationAddresses = new ArrayList<>();

    @ElementCollection
    @CollectionTable(
		name="urls",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name = "fk_persona_id"),
    	indexes= {@Index(name="idx_urls_persona_id_rank",columnList="persona_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(min=0,max=5)
    @Builder.Default
    private List<@NotNull URL> urls = new ArrayList<>();

    @Enumerated(EnumType.STRING)
    @NotNull
    private PersonaType personaType;

	@ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="person_id",foreignKey=@ForeignKey(name="fk_persona_personid_2_person_id"))
    private PersonOrm person;
}