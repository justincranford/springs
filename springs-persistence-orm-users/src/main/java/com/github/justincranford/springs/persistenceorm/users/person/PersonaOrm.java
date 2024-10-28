package com.github.justincranford.springs.persistenceorm.users.person;

import java.util.ArrayList;
import java.util.List;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.persistenceorm.users.person.enums.PersonaType;

import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.JoinColumn;
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
@Table(name="persona")
@ToString(callSuper=true)
@Builder(toBuilder=true)
@SQLDelete(sql="UPDATE persona SET pre_delete_date_time=NOW() WHERE id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="persona_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
@NoArgsConstructor
@AllArgsConstructor
@Getter(onMethod=@__(@JsonProperty))
@Setter
@Accessors(fluent=true)
public class PersonaOrm extends AbstractEntity {
	@Column(nullable=false,columnDefinition="TINYINT")
	private int rank;

    @ElementCollection
    @CollectionTable(
		name="email_address",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name="fk_email_address_persona_id"),
		uniqueConstraints={@UniqueConstraint(name="idx_email_address_persona_id_rank",columnNames={"persona_id","rank"})}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @OrderBy("personaId,rank")
    @NotNull
    @Size(min=1,max=5)
    @Builder.Default
    private List<@NotNull EmailAddressOrm> emailAddresses = new ArrayList<>(2);

    @ElementCollection
    @CollectionTable(
		name="phone_number",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name="fk_phone_number_persona_id"),
		uniqueConstraints={@UniqueConstraint(name="idx_phone_number_persona_id_rank",columnNames={"persona_id","rank"})}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @OrderBy("personaId,rank")
    @NotNull
    @Size(min=1,max=5)
    @Builder.Default
    private List<@NotNull PhoneNumberOrm> phoneNumbers = new ArrayList<>(1);

    @ElementCollection
    @CollectionTable(
		name="location_address",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name="fk_location_address_persona_id"),
		uniqueConstraints={@UniqueConstraint(name="idx_location_address_persona_id_rank",columnNames={"persona_id","rank"})}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @OrderBy("personaId,rank")
    @NotNull
    @Size(min=1,max=4)
    @Builder.Default
    private List<@NotNull LocationAddressOrm> locationAddresses = new ArrayList<>(1);

    @ElementCollection
    @CollectionTable(
		name="url",
    	joinColumns=@JoinColumn(name="personaId",referencedColumnName="id"),
    	foreignKey=@ForeignKey(name = "fk_url_persona_id"),
		uniqueConstraints={@UniqueConstraint(name="idx_url_persona_id_rank",columnNames={"persona_id","rank"})}
    )
    @org.hibernate.annotations.Cascade({org.hibernate.annotations.CascadeType.ALL})
    @OrderBy("personaId,rank")
    @NotNull
    @Size(min=0,max=5)
    @Builder.Default
    private List<@NotNull UrlOrm> urls = new ArrayList<>(0);

    @Enumerated(EnumType.STRING)
    @NotNull
    private PersonaType personaType;

	@ManyToOne(fetch=FetchType.LAZY)
    @JoinColumn(name="person_id",foreignKey=@ForeignKey(name="fk_persona_personid_2_person_id"))
    private PersonOrm person;

//    @OneToMany(mappedBy="persona",cascade=CascadeType.ALL,orphanRemoval=true,fetch=FetchType.LAZY)
//    @OrderBy("createdAt DESC")
//    @NotNull
//    @Size(min=0,max=Integer.MAX_VALUE)
//    private List<SessionOrm> sessions;
//
//    public void addSession(final SessionOrm session) {
//        addSessionWithOptionalCascade(session, true);
//	}
//    public void deleteSession(final SessionOrm session) {
//    	deleteSessionWithOptionalCascade(session, true);
//    }
//
//    /*package*/ void addSessionWithOptionalCascade(final SessionOrm session, final boolean cascade) {
//		this.sessions.add(session);
//		session.persona(this);
//        if (cascade) {
//            this.person.addSessionWithOptionalCascade(session, this, false);
//        }
//	}
//    /*package*/ void deleteSessionWithOptionalCascade(final SessionOrm session, final boolean cascade) {
//    	this.sessions.remove(session);
//        session.persona(null);
//        if (cascade) {
//        	this.person.deleteSessionWithOptionalCascade(session, false);
//        }
//	}
}