package com.github.justincranford.springs.service.webauthn.register.repository;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.lang.NonNull;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

import jakarta.persistence.Column;
import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotBlank;
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
@Table(name = "registration")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE registration SET pre_delete_date_time=NOW() WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="registration_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
public class RegistrationOrm extends AbstractEntity {
	@Column(length=86,nullable=false,updatable=false)
	@Size(min=0,max=86)
	@NotBlank
	private String sessionToken;

	@Convert(converter = PublicKeyCredentialCreationOptionsConverter.class)
	@Column(length=65535,nullable=false,updatable=false)
	@NonNull
	private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
}