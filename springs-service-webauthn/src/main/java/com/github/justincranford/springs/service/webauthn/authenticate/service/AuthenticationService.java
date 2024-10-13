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
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationRequest;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationResponse;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationSuccess;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.AuthenticationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.util.json.config.PrettyJson;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls"})
public class AuthenticationService {
	private static final int NUM_RANDOM_BYTES_SESSION_TOKEN = 32;

	@Autowired
	private PrettyJson prettyJson;
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
	public AuthenticationRequest start(@NotBlank final String username, @NotBlank final String requestUrl) {
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
		final StartAssertionOptions startAssertionOptions = StartAssertionOptions.builder()
			.timeout(300_000L) // 5 minutes
			.username(isUsernameRequest ? username : null)
			.userHandle(Optional.empty())
			.userVerification(UserVerificationRequirement.DISCOURAGED)
			.build();
		final AssertionRequest assertionRequest = this.relyingParty.startAssertion(startAssertionOptions);

		final String sessionToken = "AuthnSessionToken:" + randomByteArray(NUM_RANDOM_BYTES_SESSION_TOKEN).getBase64Url();
		final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = assertionRequest.getPublicKeyCredentialRequestOptions();
		final AuthenticationRequest.Actions actions = new AuthenticationRequest.Actions(requestUrl);
		final AuthenticationRequest authenticationRequest = AuthenticationRequest.builder()
			.sessionToken(sessionToken)
			.request(assertionRequest)
			.publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
			.username(Optional.ofNullable(username))
			.actions(actions)
			.build();
		this.authenticationRepositoryOrm.add(sessionToken, authenticationRequest);
		this.prettyJson.log(authenticationRequest);
		return authenticationRequest;
	}

	public AuthenticationSuccess finish(@NotNull AuthenticationResponse authenticationResponse) {
		try {
			this.prettyJson.log(authenticationResponse);

			final AuthenticationRequest authenticationRequest = this.authenticationRepositoryOrm.remove(authenticationResponse.getSessionToken());
			this.prettyJson.log(authenticationRequest);

			final AssertionResult authenticationResult = this.relyingParty.finishAssertion(
				FinishAssertionOptions.builder()
			        .request(authenticationRequest.getRequest())
			        .response(authenticationResponse.getCredential())
			        .build()
			);
			this.prettyJson.log(authenticationResult);

			final ByteArray                 userHandle                = authenticationResult.getCredential().getUserHandle();
			final Set<CredentialOrm>        registrationsByUserHandle = this.credentialRepositoryOrm.getRegistrationsByUserHandle(userHandle);
			final Set<RegisteredCredential> registeredCredentials     = registrationsByUserHandle.stream().map(CredentialOrm::toRegisteredCredential).collect(Collectors.toSet());
			final AuthenticatorData         authenticatorData         = authenticationResponse.getCredential().getResponse().getParsedAuthenticatorData();
			final String                    username                  = authenticationRequest.getUsername().orElse(null);
			final String                    requestId                 = authenticationRequest.getRequestId();
			return this.prettyJson.log(
				AuthenticationSuccess.builder()
					.success(true)
//					.request(authenticationRequest)
//					.response(authenticationResponse)
					.registrations(registeredCredentials)
					.authData(authenticatorData)
					.username(username)
					.sessionToken(requestId)
					.build()
			);
		} catch (AssertionFailedException e) {
			log.info("Finish authentication exception", e);
			if (e.getCause().getMessage().equals("Username not found for userHandle: Optional.empty")) {
				throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage(), e);
			}
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
		}
	}
}
