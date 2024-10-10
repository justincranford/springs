package com.github.justincranford.springs.service.webauthn.authenticate.service;

import java.net.MalformedURLException;
import java.util.Set;

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
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AssertionExtensionInputs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationInput;
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.annotation.Nullable;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls", "deprecation", "unused", "static-method"})
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
	 * @return
	 * @throws MalformedURLException
	 * @throws JsonProcessingException
	 */
	public AuthenticationRequest start(
		@Nullable final String username
	) throws MalformedURLException, JsonProcessingException {
		final boolean isUsernameRequest = Strings.isNotBlank(username);
		if (isUsernameRequest) {
			final Set<RegisteredCredential> credentials = this.credentialRepositoryOrm.getRegistrationsByUsername(username);
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

		final String requestId = randomByteArray(64).getBase64Url();
		final AuthenticationRequest authenticationRequest = new AuthenticationRequest(requestId, assertionRequest);
		this.authenticationRepositoryOrm.add(requestId, authenticationRequest);
		log.info("authenticationRequest: {}", authenticationRequest);
		return authenticationRequest;
	}

	public AuthenticationSuccess finish(final AuthenticationResponse authenticationResponse) {
		try {
			final AuthenticationRequest authenticationRequest = this.authenticationRepositoryOrm.remove(authenticationResponse.getSessionToken());
			log.info("authenticationRequest: {}", authenticationRequest);

			final AssertionResult authenticationResult = this.relyingParty.finishAssertion(
				FinishAssertionOptions.builder()
			        .request(authenticationRequest.getRequest())
			        .response(authenticationResponse.getCredential())
			        .build()
			);
			log.info("authenticationResult: {}", authenticationResult);
			final Set<RegisteredCredential> registrationsByUserHandle = this.credentialRepositoryOrm.getRegistrationsByUserHandle(authenticationResult.getCredential().getUserHandle());
			final AuthenticationSuccess authenticationSuccess = new AuthenticationSuccess(
				authenticationRequest,
				authenticationResponse,
				registrationsByUserHandle,
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
