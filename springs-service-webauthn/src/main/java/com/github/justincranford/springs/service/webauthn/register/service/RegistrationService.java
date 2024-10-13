package com.github.justincranford.springs.service.webauthn.register.service;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.databind.JsonNode;
import com.github.justincranford.springs.service.webauthn.credential.data.AttestationCertInfo;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationSuccess;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.github.justincranford.springs.util.json.config.PrettyJson;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
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

	public RegistrationRequest start(@NotBlank final String username, @NotBlank final String displayName, @Nullable final String credentialNickname, @NotBlank final String requestUrl) {
		try {
			final UserIdentity userIdentity = UserIdentity.builder()
				.name(username)
				.displayName(displayName)
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
			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = this.relyingParty
					.startRegistration(startRegistrationOptions);
			final String newSessionToken = "RegSessionToken:" + randomByteArray(NUM_RANDOM_BYTES_SESSION_TOKEN).getBase64Url();
			final RegistrationRequest.Request request = RegistrationRequest.Request.builder()
				.publicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions)
				.build();
			final RegistrationRequest registrationRequest = RegistrationRequest.builder()
				.success(true)
				.userIdentity(userIdentity)
				.username(username)
				.displayName(displayName)
				.credentialNickname(credentialNickname)
				.sessionToken(newSessionToken)
				.request(request)
				.actions(new RegistrationRequest.StartRegistrationActions(requestUrl)).build();
			this.registrationRepositoryOrm.add(newSessionToken, registrationRequest);
			this.prettyJson.log(registrationRequest);
			return registrationRequest;
		} catch (MalformedURLException e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Finish registration exception");
		}
	}

	public RegistrationSuccess finish(@NotNull RegistrationResponse registrationResponse) {
		try {
    		final String sessionToken = registrationResponse.getSessionToken();
			log.trace("Res, sessionToken: {}", sessionToken);

			final RegistrationRequest registrationRequest = this.registrationRepositoryOrm.remove(sessionToken);
			log.trace("registrationRequest: {}", registrationRequest);
			log.trace("registrationResponse: {}", registrationResponse);
			if (registrationRequest == null) {
				log.error("Invalid sessionToken: {}", sessionToken);
				throw new RegistrationFailedException(new IllegalArgumentException("Invalid sessionToken"));
			}
			this.prettyJson.log(registrationRequest);

			final UserIdentity userIdentity       = registrationRequest.getUserIdentity();
			final String       username           = registrationRequest.getUsername();
    		final String       displayName        = registrationRequest.getDisplayName();
    		final String       credentialNickname = registrationRequest.getCredentialNickname();
			log.trace("Req, userIdentity: {}, username: {}, displayName: {}, credentialNickname: {}, sessionToken: {}",
				userIdentity,
				username,
				displayName,
				credentialNickname,
				registrationRequest.getSessionToken()
			);

			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = registrationRequest.getRequest().getPublicKeyCredentialCreationOptions();
			final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential = registrationResponse.getCredential();
			final RegistrationResult registrationResult = this.relyingParty
				.finishRegistration(
					FinishRegistrationOptions.builder()
					.request(publicKeyCredentialCreationOptions)
					.response(publicKeyCredential)
					.build()
				);
			this.prettyJson.log(registrationResult);

			final CredentialOrm credentialOrm = CredentialOrm.builder()
				.credentialNickname(registrationRequest.getCredentialNickname())
				.username(registrationRequest.getUsername())
				.displayName(registrationRequest.getDisplayName())
				.userHandle(userIdentity.getId().getBase64Url())
				.credentialId(registrationResult.getKeyId().getId().getBase64Url())
				.transports(registrationResponse.getCredential().getResponse().getTransports())
				.publicKeyCose(registrationResult.getPublicKeyCose().getBase64Url())
				.signatureCount(Long.valueOf(registrationResult.getSignatureCount()))
				.backupEligible(Boolean.valueOf(registrationResult.isBackupEligible()))
				.backupState(Boolean.valueOf(registrationResult.isBackedUp()))
				.registrationTime(DateTimeUtil.nowUtcTruncatedToMilliseconds())
				.build();
			this.prettyJson.log(credentialOrm);

			this.credentialRepositoryOrm.addByUsername(username, credentialOrm);
			final RegisteredCredential registeredCredential = credentialOrm.toRegisteredCredential();
			final Optional<AttestationCertInfo> attestationCert = Optional.ofNullable(registrationResponse.getCredential().getResponse().getAttestation().getAttestationStatement().get("x5c"))
				.map(certs -> certs.get(0)).flatMap((JsonNode certDer) -> {
					try {
						return Optional.of(new ByteArray(certDer.binaryValue()));
					} catch (IOException e) {
						log.error("Failed to get binary value from x5c element: {}", certDer, e);
						return Optional.empty();
					}
				})
				.map(AttestationCertInfo::new);
			final AuthenticatorData authenticationData = registrationResponse.getCredential().getResponse().getParsedAuthenticatorData();
			final RegistrationSuccess registrationSuccess = RegistrationSuccess.builder()
				.success(true)
//				.request(registrationRequest)
//				.response(registrationResponse)
				.registration(registeredCredential)
				.attestationTrusted(true)
				.attestationCert(attestationCert)
				.authData(authenticationData)
				.username(username)
				.sessionToken(sessionToken)
				.build();
			this.prettyJson.log(registrationSuccess);

			return registrationSuccess;
		} catch (RegistrationFailedException e) {
			log.info("Finish registration exception", e);
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
		}
	}
}
