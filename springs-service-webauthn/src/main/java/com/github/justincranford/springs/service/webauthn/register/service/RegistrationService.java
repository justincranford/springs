package com.github.justincranford.springs.service.webauthn.register.service;

import static com.github.justincranford.springs.service.webauthn.register.util.ByteArrayUtil.randomByteArray;

import java.net.MalformedURLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.register.data.SuccessfulRegistrationResult;
import com.github.justincranford.springs.service.webauthn.rp.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.rp.repository.RegistrationRepositoryOrm;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.RegistrationFailedException;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls", "deprecation"})
public class RegistrationService {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RelyingParty relyingParty;
	@Autowired
	private RegistrationRepositoryOrm registrationRepositoryOrm;
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;

	public RegistrationRequest start(
		final String username,
		final String displayName,
		final String credentialNickname,
		final String requestUrl
	) throws MalformedURLException, JsonProcessingException {
		final UserIdentity userIdentity = UserIdentity.builder()
			.name(username)
			.displayName(displayName)
			.id(randomByteArray(32))
			.build();
		final StartRegistrationOptions startRegistrationOptions = StartRegistrationOptions.builder().user(userIdentity)
			.timeout(300L)
			.authenticatorSelection(
				AuthenticatorSelectionCriteria.builder()
					.authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
					.residentKey(ResidentKeyRequirement.REQUIRED)
					.userVerification(UserVerificationRequirement.PREFERRED
				).build()
			)
//			.extensions(
//				RegistrationExtensionInputs.builder()
//					.appidExclude(this.relyingParty.getAppId())
//					.credProps()
//					.uvm()
//					.largeBlob(LargeBlobSupport.PREFERRED)
//					.build()
//			)
			.build();
		final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = this.relyingParty
				.startRegistration(startRegistrationOptions);
		final String newSessionToken = randomByteArray(64).getBase64Url();
		final RegistrationRequest registrationRequest = RegistrationRequest.builder()
			.userIdentity(userIdentity)
			.username(username)
			.displayName(displayName)
			.credentialNickname(credentialNickname)
			.sessionToken(newSessionToken)
			.request(
				RegistrationRequest.Request.builder()
					.publicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions)
					.build()
			)
			.actions(
				new RegistrationRequest.StartRegistrationActions(requestUrl)
			).build();
		this.registrationRepositoryOrm.add(newSessionToken, registrationRequest);
		log.info("registrationRequest: {}", this.objectMapper.writeValueAsString(registrationRequest));
		return registrationRequest;
	}

	public SuccessfulRegistrationResult finish(final RegistrationResponse registrationResponse) {
		try {
			final String sessionToken = registrationResponse.getSessionToken();
			log.info("sessionToken: {}", sessionToken);

    		final RegistrationRequest registrationRequest = this.registrationRepositoryOrm.remove(sessionToken);
			log.info("registrationRequest: {}", registrationRequest);

			final UserIdentity userIdentity       = registrationRequest.getUserIdentity();
			final String       username           = registrationRequest.getUsername();
    		final String       displayName        = registrationRequest.getDisplayName();
    		final String       credentialNickname = registrationRequest.getCredentialNickname();
			log.info("userIdentity: {}, username: {}, displayName: {}, credentialNickname: {}",
				userIdentity,
				username,
				displayName,
				credentialNickname
			);

			final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = registrationRequest
				.getRequest().getPublicKeyCredentialCreationOptions();

			final PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential = registrationResponse
				.getCredential();

			final RegistrationResult registrationResult = this.relyingParty
				.finishRegistration(
					FinishRegistrationOptions.builder()
					.request(publicKeyCredentialCreationOptions)
					.response(publicKeyCredential)
					.build()
				);
			final RegisteredCredential registeredCredential = RegisteredCredential.builder()
				.credentialId(registrationResult.getKeyId().getId())
				.userHandle(userIdentity.getId())
				.publicKeyCose(registrationResult.getPublicKeyCose())
				.signatureCount(registrationResult.getSignatureCount())
				.backupEligible(Boolean.valueOf(registrationResult.isBackupEligible()))
				.backupState(Boolean.valueOf(registrationResult.isBackedUp()))
				.build();
			this.credentialRepositoryOrm.addRegistrationByUsername(username, registeredCredential);
			final SuccessfulRegistrationResult successfulRegistrationResult = new SuccessfulRegistrationResult(
				registrationRequest,
				registrationResponse,
				registeredCredential,
				true,
				sessionToken
			);
			log.info("successfulRegistrationResult: {}", this.objectMapper.writeValueAsString(successfulRegistrationResult));
			return successfulRegistrationResult;
		} catch (RegistrationFailedException | JsonProcessingException e) {
			log.info("Finish registration exception", e);
			throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Finish registration exception");
		}
	}
}
