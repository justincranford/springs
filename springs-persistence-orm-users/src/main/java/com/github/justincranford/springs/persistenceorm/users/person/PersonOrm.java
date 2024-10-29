package com.github.justincranford.springs.persistenceorm.users.person;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.lang.Nullable;

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

@Entity
@Audited
@Table(name="person")
@ToString(callSuper=true,exclude="password")
@SQLDelete(sql="UPDATE person SET pre_delete_date_time=NOW() WHERE id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="person_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Accessors(fluent=true)
public class PersonOrm extends AbstractEntity {
    @Column(length=64,nullable=false,unique=true)
	@Size(min=1,max=64)
	@NotNull
	@NotBlank
    private String username;

    @Embedded
    private PasswordOrm password;

    @Embedded // Use @OneToOne if Name will be an independent entity
    private NameOrm name;

    @Column
	@Nullable
    private LocalDate dateOfBirth;

    @Enumerated(EnumType.STRING)
    @Column(nullable=false,length=6)
//    @Size(min=2,max=6)
    @NotNull
    private PersonStatusType status;

    @ElementCollection
    @CollectionTable(
		name="languages",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name = "fk_languages_persona_id"),
    	indexes= {@Index(name="idx_languages_persona_id_rank",columnList="persona_id,rank")}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @OrderBy("personaId,rank")
    @NotNull
    @Size(min=1,max=4)
    @Builder.Default
    private List<@NotNull LanguageOrm> languages = new ArrayList<>();

    @ElementCollection
    @CollectionTable(
		name="timezones",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name = "fk_timezones_persona_id"),
    	indexes= {@Index(name="idx_timezones_persona_id_rank",columnList="persona_id,rank")}
    )
    @OrderColumn(name="rank")
    @NotNull
    @Size(min=1,max=4)
    @Builder.Default
    private List<@NotNull String> timezones = new ArrayList<>();

    @OneToMany(mappedBy="person",cascade=CascadeType.ALL,orphanRemoval=true,fetch=FetchType.LAZY)
    @OrderBy("id,rank")
    @NotNull
    @Size(min=0,max=4)
	@Builder.Default
    private List<PersonaOrm> personas = new ArrayList<>(1);

//    @OneToMany(mappedBy="person",cascade=CascadeType.ALL,orphanRemoval=true,fetch=FetchType.LAZY)
//    @OrderBy("createdAt DESC")
//    @NotNull
//    @Size(min=0,max=Integer.MAX_VALUE)
//    private List<SessionOrm> sessions;
//
//    public void addSession(final SessionOrm session) {
//    	this.addSession(session, this.personas.get(0));
//	}
//    public void addSession(final SessionOrm session, final PersonaOrm persona) {
//        this.addSessionWithOptionalCascade(session, persona, true);
//	}
//    public void deleteSession(final SessionOrm session) {
//    	this.deleteSessionWithOptionalCascade(session, true);
//    }
//
//	/*package*/ void addSessionWithOptionalCascade(final SessionOrm session, final PersonaOrm persona, final boolean cascade) {
//		this.sessions.add(session);
//        session.person(this);
//        if (cascade) {
//            persona.addSessionWithOptionalCascade(session, false);
//        }
//	}
//	/*package*/ void deleteSessionWithOptionalCascade(final SessionOrm session, final boolean cascade) {
//		this.sessions.remove(session);
//    	session.person(null);
//    	if (cascade) {
//        	session.persona().deleteSession(session);
//    	}
//	}
}