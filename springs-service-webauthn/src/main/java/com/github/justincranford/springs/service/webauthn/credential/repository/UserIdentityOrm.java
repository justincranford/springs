package com.github.justincranford.springs.service.webauthn.credential.repository;

import java.util.List;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.lang.NonNull;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.OneToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
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
@Table(name = "user_identity")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE user_identity SET pre_delete_date_time=NOW() WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="user_identity_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
public class UserIdentityOrm extends AbstractEntity {
    @Column(length=64,nullable=false,unique=true)
	@NonNull
	@Size(min=8,max=64)
    private String username;

    @Column(length=256,nullable=false)
	@NonNull
	@Size(min=8,max=256)
    private String displayName;

    @Column(length=64,nullable=false)
	@NonNull
	@Size(min=32,max=64)
    private byte[] userHandle;

    @JsonManagedReference
    @OneToMany(mappedBy="userIdentity",cascade=CascadeType.ALL,orphanRemoval=true)
    private List<CredentialOrm> credentials;

	public UserIdentity toUserIdentity() {
		return UserIdentity.builder()
			.name(this.username)
			.displayName(this.displayName)
			.id(new ByteArray(this.userHandle))
			.build();
	}
}
