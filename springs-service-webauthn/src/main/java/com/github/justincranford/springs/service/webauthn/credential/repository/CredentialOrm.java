package com.github.justincranford.springs.service.webauthn.credential.repository;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.decodeBase64Url;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.Set;

import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialType;
import com.yubico.webauthn.data.UserIdentity;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.Builder;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;

@RequiredArgsConstructor
@Getter
@Setter
@Builder
@SuppressWarnings({"deprecation"})
public class CredentialOrm {
	@Nullable private final String                      credentialNickname;
	@Nonnull  private final String                      username;            // UserIdentity.username
	@Nonnull  private final String                      displayName;         // UserIdentity.displayName
	@Nonnull  private final String                      userHandle;          // UserIdentity.id, RegisteredCredential.userHandle
	@Nonnull  private final String                      credentialId;        // RegisteredCredential.credentialId, PublicKeyCredentialDescriptor.id
	@Nullable private final Set<AuthenticatorTransport> transports;          // PublicKeyCredentialDescriptor.transports
	@Nonnull  private final String                      publicKeyCose;       // RegisteredCredential.publicKeyCose
	@Nonnull  private final Long                        signatureCount;      // RegisteredCredential.signatureCount
	@Nullable private final Boolean                     backupEligible;      // RegisteredCredential.backupEligible
	@Nullable private final Boolean                     backupState;         // RegisteredCredential.backupState
	@Nonnull  private final OffsetDateTime              registrationTime;

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