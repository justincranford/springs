package com.github.justincranford.springs.service.webauthn.register.service;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;

import java.util.Map;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationFinishClient;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationFinishServer;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationStartClient;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationStartServer;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationOrm;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
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
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.Nonnull;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls", "deprecation"})
public class RegistrationService {
	private static final int NUM_RANDOM_BYTES_CREDENTIAL_ID = 32;
	private static final int NUM_RANDOM_BYTES_SESSION_TOKEN = 32;
	private static final long TIMEOUT_MILLIS = 300_000L; // 5 minutes

	@Autowired
	private ObjectMapper objectMapper;
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

	@Transactional
	public RegistrationStartServer start(@Nonnull final RegistrationStartClient registrationStartClient) {
		try {
			this.prettyJson.logAndSave(registrationStartClient);

			final String sessionToken = "Register:" + randomByteArray(NUM_RANDOM_BYTES_SESSION_TOKEN).getBase64Url();

			final UserIdentity userIdentity = this.userIdentityRepositoryOrm.findByUsername(registrationStartClient.getUsername())
				.map(UserIdentityOrm::toUserIdentity).orElseGet(() -> 
					this.userIdentityRepositoryOrm.save(
				        UserIdentityOrm.builder()
				            .username(registrationStartClient.getUsername())
				            .displayName(registrationStartClient.getDisplayName())
				            .userHandle(SecureRandomUtil.randomBytes(NUM_RANDOM_BYTES_CREDENTIAL_ID))
				            .build()
					).toUserIdentity()
				);

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

			final RegistrationOrm registrationOrm = RegistrationOrm.builder()
				.sessionToken(sessionToken)
				.publicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions)
				.build();
			this.prettyJson.logAndSave(registrationOrm);
			this.registrationRepositoryOrm.save(registrationOrm);

			final RegistrationStartServer registrationStartServer = RegistrationStartServer.builder()
				.sessionToken(sessionToken)
				.publicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions)
				.build();
			this.prettyJson.logAndSave(registrationStartServer);

			return registrationStartServer;
		} catch (Exception e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Finish registration exception");
		}
	}

	@Transactional
	public RegistrationFinishServer finish(@Nonnull RegistrationFinishClient registrationFinishClient) {
		try {
			this.prettyJson.logAndSave(registrationFinishClient);
    		final String sessionToken = registrationFinishClient.getSessionToken();
			final String publicKeyCredentialJson = registrationFinishClient.getPublicKeyCredentialEncoded().replaceAll("\\\\", "");
			final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential = cleanAndDecode(publicKeyCredentialJson);
			this.prettyJson.logAndSave(publicKeyCredential);

			final Optional<RegistrationOrm> registrationOrm = this.registrationRepositoryOrm.findBySessionToken(sessionToken);
			if (registrationOrm.isEmpty()) {
				log.error("Invalid sessionToken: {}", sessionToken);
				throw new RegistrationFailedException(new IllegalArgumentException("Invalid sessionToken"));
			}
			this.prettyJson.log(registrationOrm);
			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = registrationOrm.get().publicKeyCredentialCreationOptions();
			this.prettyJson.log(publicKeyCredentialCreationOptions);

			final RegistrationResult registrationResult = this.relyingParty.finishRegistration(
				FinishRegistrationOptions.builder()
					.request(publicKeyCredentialCreationOptions)
					.response(publicKeyCredential)
					.build()
			);
			this.prettyJson.logAndSave(registrationResult);

			final UserIdentity    userIdentity    = publicKeyCredentialCreationOptions.getUser();
			final UserIdentityOrm userIdentityOrm = this.userIdentityRepositoryOrm.findByUsername(userIdentity.getName()).orElseThrow();

			final CredentialOrm credentialOrm = CredentialOrm.builder()
				.userIdentity(userIdentityOrm)
				.credentialId(registrationResult.getKeyId().getId().getBase64Url())
				.transports(publicKeyCredential.getResponse().getTransports())
				.publicKeyCose(registrationResult.getPublicKeyCose().getBase64Url())
				.signatureCount(Long.valueOf(registrationResult.getSignatureCount()))
				.backupEligible(Boolean.valueOf(registrationResult.isBackupEligible()))
				.backupState(Boolean.valueOf(registrationResult.isBackedUp()))
				.attestationObject(publicKeyCredential.getResponse().getAuthenticatorData().getBytes())
				.clientDataJSON(publicKeyCredential.getResponse().getClientDataJSON().getBytes())
				.authenticatorAttachment(registrationResult.getAuthenticatorAttachment().orElse(null))
				.type(publicKeyCredential.getType())
				.clientExtensionResults(publicKeyCredential.getClientExtensionResults())
				.build();
			this.prettyJson.log(credentialOrm);
			this.credentialRepositoryOrm.save(credentialOrm);

			final RegistrationFinishServer registrationFinishServer = RegistrationFinishServer.builder().registeredCredential(credentialOrm.toRegisteredCredential()).build();
			this.prettyJson.logAndSave(registrationFinishServer);

			return registrationFinishServer;
		} catch (Exception e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
		}
	}

	private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> cleanAndDecode(final String publicKeyCredentialJson) throws JsonProcessingException {
		log.info("publicKeyCredentialJson: {}", publicKeyCredentialJson);

		// decode into Map format
		final Map<String, Map<String, Object>> publicKeyCredentialMap = this.objectMapper.readValue(publicKeyCredentialJson, Map.class);

		// remove client-side data not supported by the server-side implementation of PublicKeyCredential
		final Map<String, Object> publicKeyCredentialResponseMap = publicKeyCredentialMap.get("response");
		final Object authenticatorData  = publicKeyCredentialResponseMap.remove("authenticatorData");
		final Object publicKey          = publicKeyCredentialResponseMap.remove("publicKey");
		final Object publicKeyAlgorithm = publicKeyCredentialResponseMap.remove("publicKeyAlgorithm");
		log.debug("Removed unsupported client-side data response.authenticatorData: {}", authenticatorData);
		log.debug("Removed unsupported client-side data response.publicKey: {}", publicKey);
		log.debug("Removed unsupported client-side data response.publicKeyAlgorithm: {}", publicKeyAlgorithm);

		// convert remaining client-side data to server-side PublicKeyCredential
		final TypeReference<PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>> valueTypeRef = new TypeReference<>() {/*empty block*/};
		final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential = this.objectMapper.convertValue(publicKeyCredentialMap, valueTypeRef);
		this.prettyJson.log(publicKeyCredential);

		return publicKeyCredential;
	}
}
