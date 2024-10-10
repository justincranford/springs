package com.github.justincranford.springs.service.webauthn.register;

import java.io.IOException;
import java.net.MalformedURLException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.register.data.SuccessfulRegistrationResult;
import com.github.justincranford.springs.service.webauthn.rp.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.rp.repository.RegistrationRepositoryOrm;
import com.github.justincranford.springs.util.basic.SecureRandomUtil;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.ResidentKeyRequirement;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping(value = "/")
@Slf4j
@SuppressWarnings({"nls", "unused", "deprecation"})
public class RegisterController {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RelyingParty relyingParty;
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;
	@Autowired
	private RegistrationRepositoryOrm registrationRepositoryOrm;

	@GetMapping(value={"/api/v1/"})
	public String index(HttpServletRequest request) throws IOException {
		final IndexResponse indexResponse = new IndexResponse(request.getRequestURL().toString());
		return this.objectMapper.writeValueAsString(indexResponse);
	}

	@PostMapping(value={"/api/v1/register", "/api/v1/register/"},consumes={"application/x-www-form-urlencoded"},produces={"application/json"})
	public RegistrationRequest startRegistration(
		final HttpServletRequest request,
		@Nonnull  @RequestParam(required=true)  final String  username,
		@Nonnull  @RequestParam(required=true)  final String  displayName,
		@Nullable @RequestParam(required=false) final String  credentialNickname,
		@Nonnull  @RequestParam(required=true)  final String  sessionToken,
		@Nullable @RequestParam(required=false) final Boolean requireResidentKey
	) throws Base64UrlException, JsonProcessingException, MalformedURLException {
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
		final StartRegistrationOptions startRegistrationOptions = StartRegistrationOptions.builder()
			.user(userIdentity)
			.timeout(300L)
			.authenticatorSelection(
				AuthenticatorSelectionCriteria.builder()
					.authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
					.residentKey(ResidentKeyRequirement.REQUIRED)
					.userVerification(UserVerificationRequirement.PREFERRED)
					.build()
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
		final RegistrationRequest registrationRequest = RegistrationRequest.builder().userIdentity(userIdentity)
			.username(username)
			.displayName(displayName)
			.credentialNickname(credentialNickname)
			.sessionToken(newSessionToken)
			.request(
				RegistrationRequest.Request.builder().publicKeyCredentialCreationOptions(publicKeyCredentialCreationOptions).build()
			)
			.actions(new RegistrationRequest.StartRegistrationActions(request.getRequestURL().toString()))
			.build();
		this.registrationRepositoryOrm.add(newSessionToken, registrationRequest);
		log.info("registrationRequest: {}", this.objectMapper.writeValueAsString(registrationRequest));
		return registrationRequest;
	}

	// /api/v1/register/finish
	@PostMapping(
		value={"/api/v1/register/finish","/api/v1/register/finish/"},
		consumes={"text/plain;charset=UTF-8"},
		produces={"application/json"}
	)
	public SuccessfulRegistrationResult finishRegistration(@RequestBody final String responseString) throws JsonMappingException, JsonProcessingException, Base64UrlException {
		try {
			log.info("responseString: {}", responseString);

			final RegistrationResponse registrationResponse = this.objectMapper.readValue(responseString, RegistrationResponse.class);
			log.info("response: {}", registrationResponse);

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
		} catch (RegistrationFailedException e) {
			log.info("Finish registration exception", e);
			throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Finish registration exception");
		}
	}

	private static ByteArray decodeBase64Url(final String idBase64Url) {
		try {
			return ByteArray.fromBase64Url(idBase64Url);
		} catch (Base64UrlException e) {
			log.info("Finish registration exception", e);
			throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Finish registration exception");
		}
	}

	private static ByteArray randomByteArray(final int numBytes) {
		return new ByteArray(SecureRandomUtil.randomBytes(numBytes));
	}
}