package com.github.justincranford.springs.service.webauthn.credential.repository;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.decodeBase64Url;

import java.util.Optional;
import java.util.Set;

import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.service.webauthn.credential.repository.converter.SetAuthenticatorTransportConverter;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.UserIdentity;

import jakarta.persistence.Convert;
import jakarta.persistence.Entity;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.experimental.Accessors;

@Entity
@Audited
@Table(name = "credential")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE credential SET pre_delete_date_time=NOW() WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.WHERE_CLAUSE)
@SequenceGenerator(sequenceName="credential_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_MEDIUM)
@SuppressWarnings({"deprecation"})
public class CredentialOrm extends AbstractEntity {
	private String                      credentialNickname;
	private String                      username;            // UserIdentity.username
	private String                      userHandle;          // UserIdentity.id, RegisteredCredential.userHandle
	private String                      displayName;         // UserIdentity.displayName
	private String                      credentialId;        // RegisteredCredential.credentialId, PublicKeyCredentialDescriptor.id
	@Convert(converter = SetAuthenticatorTransportConverter.class)
	private Set<AuthenticatorTransport> transports;          // PublicKeyCredentialDescriptor.transports
	private String                      publicKeyCose;       // RegisteredCredential.publicKeyCose
	private Long                        signatureCount;      // RegisteredCredential.signatureCount
	private Boolean                     backupEligible;      // RegisteredCredential.backupEligible
	private Boolean                     backupState;         // RegisteredCredential.backupState
	private Boolean                     discoverable;        // Passkey?
	private byte[]                      attestationObject;   // for future reference
	private byte[]                      clientDataJSON;      // for re-verify signature

	public UserIdentity toUserIdentity() {
		return UserIdentity.builder()
			.name(this.username)
			.displayName(this.displayName)
			.id(decodeBase64Url(this.userHandle))
			.build();
	}

	public PublicKeyCredentialDescriptor toPublicKeyCredentialDescriptor() {
		return PublicKeyCredentialDescriptor.builder()
			.id(decodeBase64Url(this.credentialId))
			.transports(Optional.ofNullable(this.transports))
            .type(PublicKeyCredentialType.PUBLIC_KEY)
			.build();
	}

	public RegisteredCredential toRegisteredCredential() {
		return RegisteredCredential.builder()
			.credentialId(decodeBase64Url(this.credentialId))
			.userHandle(decodeBase64Url(this.userHandle))
			.publicKeyCose(decodeBase64Url(this.publicKeyCose))
			.signatureCount(this.signatureCount.longValue())
			.backupEligible(this.backupEligible)
			.backupState(this.backupState)
			.build();
	}
}