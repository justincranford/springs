package com.github.justincranford.springs.persistenceorm.users.person;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonStatusType;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrm;
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
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.lang.Nullable;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

@Entity
@Audited
@Table(name="person")
@SQLDelete(sql="UPDATE person SET pre_delete_date_time=CURRENT_TIMESTAMP WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.SQL_WHERE_CLAUSE)
@SequenceGenerator(sequenceName="person_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Accessors(fluent=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@ToString(callSuper=true,exclude="password")
public class PersonOrm extends AbstractEntity {
    @Column(length=64,nullable=false,unique=true)
	@Size(min=5,max=64)
	@NotNull
	@NotBlank
    private String username;

    @Column(length=128)
    @Size(min=8, max=128)
    @Nullable
    private byte[] webauthnId;

    @Embedded
    private PasswordOrm password;

    @Embedded // Use @OneToOne if Name will be an independent entity
    private NameOrm name;

    @Column
	@Nullable
    private LocalDate dateOfBirth;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false,length=3)
    @NotNull
    private PersonStatusType personStatus;

    @ElementCollection
    @CollectionTable(
		name="person_languages",
    	joinColumns=@JoinColumn(name="personInternalId",referencedColumnName="internalId"),
    	foreignKey=@ForeignKey(name = "fk_languages_person_internal_id"),
    	indexes= {@Index(name="idx_languages_person_internal_id_rank",columnList="person_internal_id,rank")}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @OrderBy("person_internal_id,rank")
    @NotNull
    @Size(max=4)
    @Builder.Default
    private List<@NotNull LanguageOrm> personLanguages = new ArrayList<>();

    @ElementCollection
    @CollectionTable(
		name="person_timezones",
    	joinColumns=@JoinColumn(name="personInternalId",referencedColumnName="internalId"),
    	foreignKey=@ForeignKey(name = "fk_person_timezones_person_internal_id"),
    	indexes= {@Index(name="idx_person_timezones_person_internal_id_rank",columnList="person_internal_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(max=4)
    @Builder.Default
    private List<@NotNull String> personTimeZones = new ArrayList<>();

    @JsonManagedReference
    @OneToMany(mappedBy="person",cascade=CascadeType.ALL,orphanRemoval=true,fetch=FetchType.LAZY)
    @OrderBy("id,rank")
    @NotNull
    @Size(max=4)
	@Builder.Default
    private List<PersonaOrm> personas = new ArrayList<>(1);
}
