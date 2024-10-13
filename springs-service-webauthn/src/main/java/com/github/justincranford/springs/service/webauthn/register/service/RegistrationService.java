package com.github.justincranford.springs.service.webauthn.register.service;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;

import java.net.MalformedURLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationSuccess;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.util.basic.DateTimeUtil;
import com.yubico.webauthn.FinishRegistrationOptions;
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
		final String  username,
		final String  displayName,
		final String  credentialNickname,
		final String  sessionToken,
		final Boolean requireResidentKey,
		final String  requestUrl
	) throws MalformedURLException, JsonProcessingException {
		log.info("username: {}, displayName: {}, credentialNickname: {}, sessionToken: {}, requireResidentKey: {}",
			username,
			displayName,
			credentialNickname,
			sessionToken,
			requireResidentKey
		);
		final UserIdentity userIdentity = UserIdentity.builder()
			.name(username)
			.displayName(displayName)
			.id(randomByteArray(32))
			.build();
		final StartRegistrationOptions startRegistrationOptions = StartRegistrationOptions.builder().user(userIdentity)
			.timeout(300_000L) // 5 minutes
			.authenticatorSelection(
				AuthenticatorSelectionCriteria.builder()
					.authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
					.residentKey(ResidentKeyRequirement.PREFERRED)
					.userVerification(UserVerificationRequirement.DISCOURAGED
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
		final String newRequestId = "RegRequestId:" + randomByteArray(16).getBase64Url();
		final String newSessionToken = "RegSessionToken" + randomByteArray(16).getBase64Url();
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
		this.registrationRepositoryOrm.add(newRequestId, registrationRequest);
		this.registrationRepositoryOrm.add(newSessionToken, registrationRequest);
		log.info("registrationRequest: {}", this.objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(registrationRequest));
		return registrationRequest;
	}

	public RegistrationSuccess finish(final RegistrationResponse registrationResponse) {
		try {
    		final String sessionToken = registrationResponse.getSessionToken();
			log.trace("Res, sessionToken: {}", sessionToken);

			final RegistrationRequest registrationRequest = this.registrationRepositoryOrm.remove(sessionToken);
			log.trace("registrationRequest: {}", registrationRequest);
			log.trace("registrationRequest: {}", registrationResponse);
			if (registrationRequest == null) {
				log.error("Invalid sessionToken: {}", sessionToken);
				throw new RegistrationFailedException(new IllegalArgumentException("Invalid sessionToken"));
			}

			log.info("registrationRequest: {}", this.objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(registrationRequest));
			log.info("registrationResponse: {}", this.objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(registrationResponse));

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
			log.trace("registrationResult: {}", publicKeyCredential);
			log.info("registrationResult: {}", this.objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(publicKeyCredential));

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
			log.info("credentialOrm: {}", credentialOrm);
			log.info("credentialOrm: {}", this.objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(credentialOrm));

			this.credentialRepositoryOrm.addByUsername(username, credentialOrm);
			final RegistrationSuccess successfulRegistrationResult = new RegistrationSuccess(
				registrationRequest,
				registrationResponse,
				credentialOrm.toRegisteredCredential(),
				true,
				sessionToken
			);
			log.info("successfulRegistrationResult: {}", successfulRegistrationResult);
			log.info("successfulRegistrationResult: {}", this.objectMapper.writer().withDefaultPrettyPrinter().writeValueAsString(successfulRegistrationResult));

			return successfulRegistrationResult;
		} catch (RegistrationFailedException | JsonProcessingException e) {
			log.info("Finish registration exception", e);
			throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Finish registration exception");
		}
	}
}
