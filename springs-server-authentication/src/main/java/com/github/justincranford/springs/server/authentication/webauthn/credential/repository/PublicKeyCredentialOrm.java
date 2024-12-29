package com.github.justincranford.springs.server.authentication.webauthn.credential.repository;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.github.justincranford.springs.persistenceorm.base.entity.AbstractEntity;
import com.github.justincranford.springs.server.authentication.webauthn.credential.converter.BytesConverter;
import com.github.justincranford.springs.server.authentication.webauthn.credential.converter.PublicKeyCoseConverter;
import com.github.justincranford.springs.server.authentication.webauthn.credential.converter.PublicKeyCredentialTypeConverter;
import com.github.justincranford.springs.server.authentication.webauthn.credential.converter.SetAuthenticatorTransportConverter;
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
import org.hibernate.annotations.SQLDelete;
import org.hibernate.annotations.SQLRestriction;
import org.hibernate.envers.Audited;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;

import java.time.Instant;
import java.util.Set;

@Entity
@Audited
@Table(name="public_key_credential")
@Getter(onMethod=@__(@JsonProperty))
@Setter
@ToString(callSuper=true)
@Builder(toBuilder=true)
@NoArgsConstructor
@AllArgsConstructor
@Accessors(fluent=true)
@SQLDelete(sql="UPDATE public_key_credential SET pre_delete_date_time=CURRENT_TIMESTAMP WHERE internal_id=? AND version=?")
@SQLRestriction(AbstractEntity.SQL_WHERE_CLAUSE)
@SequenceGenerator(sequenceName="public_key_credential_sequence",name=AbstractEntity.SEQUENCE_ID,initialValue=AbstractEntity.SEQUENCE_ID_INITIAL_VALUE,allocationSize=AbstractEntity.SEQUENCE_ID_ALLOCATION_SIZE_SMALL)
public class PublicKeyCredentialOrm extends AbstractEntity implements CredentialRecord {
	@Convert(converter = PublicKeyCredentialTypeConverter.class)
	private PublicKeyCredentialType            credentialType;
	@Convert(converter = BytesConverter.class)
	private Bytes                              credentialId;
	@Convert(converter = PublicKeyCoseConverter.class)
	private PublicKeyCose                      publicKey;
	private Long                               signatureCount;
	private Boolean                            uvInitialized;
	@Convert(converter = SetAuthenticatorTransportConverter.class)
	private Set<AuthenticatorTransport>        transports;
	private Boolean                            backupEligible;
	private Boolean                            backupState;
	@Convert(converter = BytesConverter.class)
	private Bytes                              userEntityUserId;
	@Convert(converter = BytesConverter.class)
	private Bytes                              attestationObject;
	@Convert(converter = BytesConverter.class)
	private Bytes                              attestationClientDataJSON;
	private String                             label;
	private Instant                            lastUsed;
	private Instant                            created;

	@Override
	public PublicKeyCredentialType getCredentialType() {
		return this.credentialType;
	}

	@Override
	public Bytes getCredentialId() {
		return this.credentialId;
	}

	@Override
	public PublicKeyCose getPublicKey() {
		return this.publicKey;
	}

	@Override
	public long getSignatureCount() {
		return this.signatureCount;
	}

	@Override
	public boolean isUvInitialized() {
		return this.uvInitialized;
	}

	@Override
	public Set<AuthenticatorTransport> getTransports() {
		return this.transports;
	}

	@Override
	public boolean isBackupEligible() {
		return this.backupEligible;
	}

	@Override
	public boolean isBackupState() {
		return this.backupState;
	}

	@Override
	public Bytes getUserEntityUserId() {
		return this.userEntityUserId;
	}

	@Override
	public Bytes getAttestationObject() {
		return this.attestationObject;
	}

	@Override
	public Bytes getAttestationClientDataJSON() {
		return this.attestationClientDataJSON;
	}

	@Override
	public String getLabel() {
		return this.label;
	}

	@Override
	public Instant getLastUsed() {
		return this.lastUsed;
	}

	@Override
	public Instant getCreated() {
		return this.created;
	}
}
