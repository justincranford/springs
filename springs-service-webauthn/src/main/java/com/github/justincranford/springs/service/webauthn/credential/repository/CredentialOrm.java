package com.github.justincranford.springs.service.webauthn.credential.repository;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.UserIdentity;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.With;

@Value
@Builder
@With
@SuppressWarnings({"deprecation"})
public class CredentialOrm {
	private UserIdentity userIdentity;

	private Optional<String> credentialNickname;

	private SortedSet<AuthenticatorTransport> transports;

	@JsonIgnore
	private Instant registrationTime;

	private RegisteredCredential credential;

	private Optional<Object> attestationMetadata;

	@JsonProperty("registrationTime")
	public String getRegistrationTimestamp() {
		return this.registrationTime.toString();
	}

	public String getUsername() {
		return this.userIdentity.getName();
	}

	public @NonNull ByteArray getCredentialId() {
		return this.credential.getCredentialId();
	}

	public @NonNull ByteArray getUserHandle() {
		return this.userIdentity.getId();
	}

	public @NonNull ByteArray getPublicKeyCose() {
		return this.credential.getPublicKeyCose();
	}

	public long getSignatureCount() {
		return this.credential.getSignatureCount();
	}

	public Optional<Set<AuthenticatorTransport>> getTransports() {
		return Optional.ofNullable(this.transports);
	}

	public Optional<Boolean> isBackupEligible() {
		return this.credential.isBackupEligible();
	}

	public Optional<Boolean> isBackedUp() {
		return this.credential.isBackedUp();
	}
}