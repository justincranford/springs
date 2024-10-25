package com.github.justincranford.springs.persistenceorm.users.person;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.enums.Status;

import jakarta.persistence.CascadeType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Embedded;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OrderBy;
import jakarta.persistence.OrderColumn;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
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
@Table(name="person")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE person SET pre_delete_date_time=NOW() WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="person_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
public class PersonOrm extends AbstractEntity {
    @Column(length=64,nullable=false,unique=true)
	@Size(min=8,max=64)
	@NotNull
	@NotBlank
    private String username;

    @Column(length=64)
	@Size(min=8,max=64)
	@Null
    private String password;

    @Embedded // TODO OneToOne?
	@Null
    private Name name;

    @Column
	@Null
    private LocalDate dateOfBirth;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false,length=50)
    @Size(min=3,max=50)
    @NotNull
    private Status status;

    @OneToMany(mappedBy="person",cascade=CascadeType.ALL,orphanRemoval=true,fetch=FetchType.LAZY)
    @OrderBy("internalId")
	@Null
    private List<PersonaOrm> personas;

    @ElementCollection
    @CollectionTable(
		name="languages",
    	joinColumns=@JoinColumn(name="personaInternalId",referencedColumnName="internalId"),
    	foreignKey=@ForeignKey(name = "fk_persona_internal_id"),
    	indexes= {@Index(name="idx_languages_persona_internal_id_rank",columnList="persona_internal_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(min=1,max=4)
    @Builder.Default
    private List<@NotNull Language> languages = new ArrayList<>();

    @ElementCollection
    @CollectionTable(
		name="timezones",
    	joinColumns=@JoinColumn(name="personaInternalId",referencedColumnName="internalId"),
    	foreignKey=@ForeignKey(name = "fk_persona_internal_id"),
    	indexes= {@Index(name="idx_timezones_persona_internal_id_rank",columnList="persona_internal_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(min=1,max=4)
    @Builder.Default
    private List<@NotNull String> timezones = new ArrayList<>();
}