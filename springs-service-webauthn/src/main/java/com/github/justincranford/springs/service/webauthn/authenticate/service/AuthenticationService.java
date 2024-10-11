package com.github.justincranford.springs.service.webauthn.authenticate.service;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;

import java.net.MalformedURLException;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationRequest;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationResponse;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationSuccess;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.AuthenticationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AssertionExtensionInputs;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls"})
public class AuthenticationService {
	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private RelyingParty relyingParty;
	@Autowired
	private AuthenticationRepositoryOrm authenticationRepositoryOrm;
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;

	/**
	 * 
	 * @param username Non-blank for Webauthn, null for Passkey
	 * @return Authentication assertion challenge
	 * @throws MalformedURLException
	 * @throws JsonProcessingException
	 */
	public AuthenticationRequest start(
		@Nullable final String username,
		@Nonnull  final String requestUrl
	) throws MalformedURLException, JsonProcessingException {
		final boolean isUsernameRequest = Strings.isNotBlank(username);
		if (isUsernameRequest) {
			final Set<CredentialOrm> credentials = this.credentialRepositoryOrm.getByUsername(username);
			if (credentials.isEmpty()) {
				log.warn("Authenticate with username {} won't work because it does not exist", username);
			} else {
				log.info("Authenticate with username {} may work because it exists", username);
			}
		} else {
			log.info("Authenticate with passkey (aka without username)", username);
		}
		final AssertionRequest assertionRequest = this.relyingParty.startAssertion(
			StartAssertionOptions.builder()
				.timeout(300_000L) // 5 minutes
				.username(isUsernameRequest ? username : null)
				.userVerification(UserVerificationRequirement.PREFERRED)
				.extensions(
					AssertionExtensionInputs.builder()
						.appid(this.relyingParty.getAppId())
						.uvm()
						.build()
				)
				.build()
		);

		final String requestId = "AuthnRequestId:" + randomByteArray(16).getBase64Url();
		final String sessionToken = "AuthnSessionToken:" + randomByteArray(16).getBase64Url();
		final AuthenticationRequest authenticationRequest = AuthenticationRequest.builder()
			.requestId(requestId)
			.sessionToken(sessionToken)
			.request(assertionRequest)
			.publicKeyCredentialRequestOptions(assertionRequest.getPublicKeyCredentialRequestOptions())
			.username(Optional.ofNullable(username))
			.actions(new AuthenticationRequest.Actions(requestUrl))
			.build();
		this.authenticationRepositoryOrm.add(requestId, authenticationRequest);
		this.authenticationRepositoryOrm.add(sessionToken, authenticationRequest);
		log.info("authenticationRequest: {}", authenticationRequest);
		return authenticationRequest;
	}

	public AuthenticationSuccess finish(final AuthenticationResponse authenticationResponse) {
		try {
			log.info("authenticationResponse: {}", authenticationResponse);

			final AuthenticationRequest authenticationRequest = this.authenticationRepositoryOrm.remove(authenticationResponse.getSessionToken());
			log.info("authenticationRequest: {}", authenticationRequest);

			final AssertionResult authenticationResult = this.relyingParty.finishAssertion(
				FinishAssertionOptions.builder()
			        .request(authenticationRequest.getRequest())
			        .response(authenticationResponse.getCredential())
			        .build()
			);
			log.info("authenticationResult: {}", authenticationResult);
			final Set<CredentialOrm> registrationsByUserHandle = this.credentialRepositoryOrm.getRegistrationsByUserHandle(authenticationResult.getCredential().getUserHandle());
			final AuthenticationSuccess authenticationSuccess = new AuthenticationSuccess(
				authenticationRequest,
				authenticationResponse,
				registrationsByUserHandle.stream().map(CredentialOrm::toRegisteredCredential).collect(Collectors.toSet()),
				authenticationResponse.getCredential().getResponse().getParsedAuthenticatorData(),
				authenticationRequest.getUsername().get(),
				authenticationRequest.getRequestId()
			);
	        log.info("authenticationSuccess: {}", this.objectMapper.writeValueAsString(authenticationSuccess));
	        return authenticationSuccess;
		} catch (AssertionFailedException | JsonProcessingException e) {
			log.info("Finish authentication exception", e);
			throw new HttpClientErrorException(HttpStatus.BAD_REQUEST, "Finish authentication exception");
		}
	}
}
