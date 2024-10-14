package com.github.justincranford.springs.service.webauthn.register.service;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationClientStart;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationServerStart;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationClientFinish;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationServerFinish;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.json.config.PrettyJson;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.Nonnull;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls", "deprecation"})
public class RegistrationService {
	private static final int NUM_RANDOM_BYTES_CREDENTIAL_ID = 32;
	private static final int NUM_RANDOM_BYTES_SESSION_TOKEN = 32;

	@Autowired
	private PrettyJson prettyJson;
	@Autowired
	private RelyingParty relyingParty;
	@Autowired
	private RegistrationRepositoryOrm registrationRepositoryOrm;
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;

	public RegistrationServerStart start(@Nonnull final RegistrationClientStart registrationClientStart) {
		try {
			final String sessionToken = "RegSessionToken:" + randomByteArray(NUM_RANDOM_BYTES_SESSION_TOKEN).getBase64Url();
			final UserIdentity userIdentity = UserIdentity.builder()
				.name(registrationClientStart.getUsername())
				.displayName(registrationClientStart.getDisplayName())
				.id(randomByteArray(NUM_RANDOM_BYTES_CREDENTIAL_ID))
				.build();
			final StartRegistrationOptions startRegistrationOptions = StartRegistrationOptions.builder().user(userIdentity)
				.timeout(300_000L) // 5 minutes
				.authenticatorSelection(
					AuthenticatorSelectionCriteria.builder()
//						.authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
						.residentKey(ResidentKeyRequirement.PREFERRED)
						.userVerification(UserVerificationRequirement.DISCOURAGED)
					.build()
				)
				.build();
			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = this.relyingParty.startRegistration(startRegistrationOptions);
			final RegistrationServerStart registrationServerStart = RegistrationServerStart.builder()
				.sessionToken(sessionToken)
				.userIdentity(userIdentity)
				.publicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions)
				.build();
			this.registrationRepositoryOrm.add(sessionToken, registrationServerStart);
			this.prettyJson.log(registrationServerStart);
			return registrationServerStart;
		} catch (Exception e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Finish registration exception");
		}
	}

	public RegistrationServerFinish finish(@Nonnull RegistrationClientFinish registrationClientFinish) {
		try {
			this.prettyJson.log(registrationClientFinish);
    		final String sessionToken = registrationClientFinish.getSessionToken();

			final RegistrationServerStart registrationServerStart = this.registrationRepositoryOrm.remove(sessionToken);
			if (registrationServerStart == null) {
				log.error("Invalid sessionToken: {}", sessionToken);
				throw new RegistrationFailedException(new IllegalArgumentException("Invalid sessionToken"));
			}
			this.prettyJson.log(registrationServerStart);

			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = registrationServerStart.getPublicKeyCredentialCreationOptions();
			final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential = registrationClientFinish.getPublicKeyCredential();
			final RegistrationResult registrationResult = this.relyingParty
				.finishRegistration(
					FinishRegistrationOptions.builder().request(publicKeyCredentialCreationOptions).response(publicKeyCredential).build()
				);
			this.prettyJson.log(registrationResult);

			final CredentialOrm credentialOrm = CredentialOrm.builder()
				.username(registrationServerStart.getUserIdentity().getName())
				.displayName(registrationServerStart.getUserIdentity().getDisplayName())
				.userHandle(registrationServerStart.getUserIdentity().getId().getBase64Url())
				.credentialId(registrationResult.getKeyId().getId().getBase64Url())
				.transports(registrationClientFinish.getPublicKeyCredential().getResponse().getTransports())
				.publicKeyCose(registrationResult.getPublicKeyCose().getBase64Url())
				.signatureCount(Long.valueOf(registrationResult.getSignatureCount()))
				.backupEligible(Boolean.valueOf(registrationResult.isBackupEligible()))
				.backupState(Boolean.valueOf(registrationResult.isBackedUp()))
				.registrationTime(DateTimeUtil.nowUtcTruncatedToMilliseconds())
				.build();
			this.prettyJson.log(credentialOrm);

			this.credentialRepositoryOrm.addByUsername(registrationServerStart.getUserIdentity().getName(), credentialOrm);
			final RegistrationServerFinish registrationServerFinish = RegistrationServerFinish.builder()
				.registeredCredential(credentialOrm.toRegisteredCredential())
				.build();
			this.prettyJson.log(registrationServerFinish);

			return registrationServerFinish;
		} catch (RegistrationFailedException e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
		}
	}
}
