package com.github.justincranford.springs.service.webauthn.register.service;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationFinishClient;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationFinishServer;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationStartClient;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationStartServer;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.github.justincranford.springs.util.json.config.PrettyJson;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.Nonnull;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls", "deprecation"})
public class RegistrationService {
	private static final int NUM_RANDOM_BYTES_CREDENTIAL_ID = 32;
	private static final int NUM_RANDOM_BYTES_SESSION_TOKEN = 32;
	private static final long TIMEOUT_MILLIS = 300_000L; // 5 minutes

	@Autowired
	private PrettyJson prettyJson;
	@Autowired
	private RelyingParty relyingParty;
	@Autowired
	private RegistrationRepositoryOrm registrationRepositoryOrm;
	@Autowired
	private UserIdentityRepositoryOrm userIdentityRepositoryOrm;
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;

	public RegistrationStartServer start(@Nonnull final RegistrationStartClient registrationStartClient) {
		try {
			this.prettyJson.logAndSave(registrationStartClient);

			final String sessionToken = "Register:" + randomByteArray(NUM_RANDOM_BYTES_SESSION_TOKEN).getBase64Url();

			final UserIdentityOrm userIdentityOrm = getOrCreate(registrationStartClient.getUsername(), registrationStartClient.getDisplayName());
			final UserIdentity    userIdentity    = toUserIdentity(userIdentityOrm);

			final StartRegistrationOptions startRegistrationOptions = StartRegistrationOptions.builder().user(userIdentity)
				.timeout(TIMEOUT_MILLIS)
				.authenticatorSelection(
					AuthenticatorSelectionCriteria.builder()
//						.authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
						.residentKey(registrationStartClient.getResidentKeyRequirement())
						.userVerification(UserVerificationRequirement.DISCOURAGED)
					.build()
				)
				.build();

			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = this.relyingParty.startRegistration(startRegistrationOptions);

			final RegistrationStartServer registrationStartServer = RegistrationStartServer.builder()
				.sessionToken(sessionToken)
				.publicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions)
				.build();
			this.prettyJson.logAndSave(registrationStartServer);

			this.registrationRepositoryOrm.add(sessionToken, registrationStartServer);
			return registrationStartServer;
		} catch (Exception e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Finish registration exception");
		}
	}

	public RegistrationFinishServer finish(@Nonnull RegistrationFinishClient registrationFinishClient) {
		try {
			this.prettyJson.logAndSave(registrationFinishClient);
    		final String sessionToken = registrationFinishClient.getSessionToken();

			final RegistrationStartServer registrationStartServer = this.registrationRepositoryOrm.remove(sessionToken);
			if (registrationStartServer == null) {
				log.error("Invalid sessionToken: {}", sessionToken);
				throw new RegistrationFailedException(new IllegalArgumentException("Invalid sessionToken"));
			}
			this.prettyJson.log(registrationStartServer);

			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = registrationStartServer.getPublicKeyCredentialCreationOptions();
			final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential = registrationFinishClient.getPublicKeyCredential();
			final RegistrationResult registrationResult = this.relyingParty
				.finishRegistration(
					FinishRegistrationOptions.builder().request(publicKeyCredentialCreationOptions).response(publicKeyCredential).build()
				);
			this.prettyJson.logAndSave(registrationResult);

			final UserIdentity userIdentity = registrationStartServer.getPublicKeyCredentialCreationOptions().getUser();
			final CredentialOrm credentialOrm = CredentialOrm.builder()
				.username(userIdentity.getName())
				.displayName(userIdentity.getDisplayName())
				.userHandle(userIdentity.getId().getBase64Url())
				.credentialId(registrationResult.getKeyId().getId().getBase64Url())
				.transports(registrationFinishClient.getPublicKeyCredential().getResponse().getTransports())
				.publicKeyCose(registrationResult.getPublicKeyCose().getBase64Url())
				.signatureCount(Long.valueOf(registrationResult.getSignatureCount()))
				.backupEligible(Boolean.valueOf(registrationResult.isBackupEligible()))
				.backupState(Boolean.valueOf(registrationResult.isBackedUp()))
				.registrationTime(DateTimeUtil.nowUtcTruncatedToMilliseconds())
				.build();
			this.prettyJson.log(credentialOrm);
			this.credentialRepositoryOrm.addByUsername(userIdentity.getName(), credentialOrm);

			final RegistrationFinishServer registrationFinishServer = RegistrationFinishServer.builder().registeredCredential(credentialOrm.toRegisteredCredential()).build();
			this.prettyJson.logAndSave(registrationFinishServer);

			return registrationFinishServer;
		} catch (Exception e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
		}
	}

	private UserIdentityOrm getOrCreate(final String username, final String displayName) {
		UserIdentityOrm userIdentityOrm = this.userIdentityRepositoryOrm.get(username);
		if (userIdentityOrm == null) {
			userIdentityOrm = UserIdentityOrm.builder()
				.username(username)
				.displayName(displayName)
				.userHandle(SecureRandomUtil.randomBytes(NUM_RANDOM_BYTES_CREDENTIAL_ID))
				.build();
			this.userIdentityRepositoryOrm.create(userIdentityOrm);
		} else {
			log.warn("Different displayName");
		}
		return userIdentityOrm;
	}

	private static UserIdentity toUserIdentity(final UserIdentityOrm userIdentityOrm) {
		final UserIdentity userIdentity = UserIdentity.builder()
			.name(userIdentityOrm.username())
			.displayName(userIdentityOrm.displayName())
			.id(new ByteArray(userIdentityOrm.userHandle()))
			.build();
		return userIdentity;
	}
}
