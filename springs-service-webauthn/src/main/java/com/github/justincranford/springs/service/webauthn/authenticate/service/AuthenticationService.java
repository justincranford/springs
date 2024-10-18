package com.github.justincranford.springs.service.webauthn.authenticate.service;

import static com.github.justincranford.springs.service.webauthn.util.ByteArrayUtil.randomByteArray;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.apache.logging.log4j.util.Strings;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationFinishClient;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationFinishServer;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationStartClient;
import com.github.justincranford.springs.service.webauthn.authenticate.data.AuthenticationStartServer;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.AuthenticationOrm;
import com.github.justincranford.springs.service.webauthn.authenticate.repository.AuthenticationRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryFacade;
import com.github.justincranford.springs.service.webauthn.credential.repository.CredentialRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityOrm;
import com.github.justincranford.springs.service.webauthn.credential.repository.UserIdentityRepositoryOrm;
import com.github.justincranford.springs.service.webauthn.register.repository.RegistrationOrm;
import com.github.justincranford.springs.util.json.config.PrettyJson;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;

import jakarta.transaction.Transactional;
import jakarta.validation.constraints.NotNull;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@SuppressWarnings({"nls"})
public class AuthenticationService {
	private static final int NUM_RANDOM_BYTES_SESSION_TOKEN = 32;

	@Autowired
	private ObjectMapper objectMapper;
	@Autowired
	private PrettyJson prettyJson;
	@Autowired
	private RelyingParty relyingParty;
	@Autowired
	private AuthenticationRepositoryOrm authenticationRepositoryOrm;
	@Autowired
	private CredentialRepositoryOrm credentialRepositoryOrm;
	@Autowired
	private UserIdentityRepositoryOrm userIdentityRepositoryOrm;
	@Autowired
	private CredentialRepositoryFacade credentialRepositoryFacade;

	@Transactional
	public AuthenticationStartServer start(@NotNull final AuthenticationStartClient authenticationStartClient) {
		try {
			this.prettyJson.logAndSave(authenticationStartClient);

			final String sessionToken = "Authenticate:" + randomByteArray(NUM_RANDOM_BYTES_SESSION_TOKEN).getBase64Url();

			final String username = authenticationStartClient.getUsername();

			final boolean isUsernameRequest = Strings.isNotBlank(username);
			if (isUsernameRequest) {
				final Set<PublicKeyCredentialDescriptor> publicKeyCredentialDescriptors = this.credentialRepositoryFacade.getCredentialIdsForUsername(authenticationStartClient.getUsername());
				if (publicKeyCredentialDescriptors.isEmpty()) {
					log.warn("Authenticate with username {} won't work because it does not exist", authenticationStartClient.getUsername());
				} else {
					log.info("Authenticate with username {} may work because it exists", authenticationStartClient.getUsername());
				}
			} else {
				log.info("Authenticate with passkey (aka without username)", authenticationStartClient.getUsername());
			}

			final StartAssertionOptions startAssertionOptions = StartAssertionOptions.builder()
				.timeout(300_000L) // 5 minutes
				.username(isUsernameRequest ? username : null)
				.userHandle(Optional.empty())
				.userVerification(UserVerificationRequirement.DISCOURAGED)
				.build();
			final AssertionRequest assertionRequest = this.relyingParty.startAssertion(startAssertionOptions);

			final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = assertionRequest.getPublicKeyCredentialRequestOptions();

			final AuthenticationOrm authenticationOrm = AuthenticationOrm.builder()
				.sessionToken(sessionToken)
				.publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
				.build();
			this.prettyJson.logAndSave(authenticationOrm);
			this.authenticationRepositoryOrm.save(authenticationOrm);

			final AuthenticationStartServer authenticationStartServer = AuthenticationStartServer.builder()
				.sessionToken(sessionToken)
				.publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
				.build();
			this.prettyJson.log(authenticationStartServer);

			return authenticationStartServer;
		} catch (Exception e) {
			log.info("Start authentication exception", e);
			throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Start authentication exception");
		}
	}

	@Transactional
	public AuthenticationFinishServer finish(@NotNull AuthenticationFinishClient authenticationFinishClient) {
		try {
			this.prettyJson.log(authenticationFinishClient);
    		final String sessionToken = authenticationFinishClient.getSessionToken();
			final String publicKeyAssertionJson = authenticationFinishClient.getPublicKeyCredentialEncoded().replaceAll("\\\\", "");
			final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> publicKeyCredential = cleanAndDecode(publicKeyAssertionJson);
			this.prettyJson.logAndSave(publicKeyCredential);

			final Optional<AuthenticationOrm> authenticationOrm = this.authenticationRepositoryOrm.findBySessionToken(sessionToken);
			if (authenticationOrm.isEmpty()) {
				log.error("Invalid sessionToken: {}", sessionToken);
				throw new AssertionFailedException(new IllegalArgumentException("Invalid sessionToken"));
			}
			this.prettyJson.log(authenticationOrm);
			final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = authenticationOrm.get().publicKeyCredentialRequestOptions();
			this.prettyJson.log(publicKeyCredentialRequestOptions);

			final String credentialId = publicKeyCredential.getId().getBase64Url();
			final List<CredentialOrm> credentialOrms = this.credentialRepositoryOrm.findByCredentialIdOrderByCreatedDateDesc(credentialId);
			if (credentialOrms.isEmpty()) {
				log.error("Invalid credentialId: {}", credentialId);
				throw new RegistrationFailedException(new IllegalArgumentException("Invalid credentialId"));
			} else if (credentialOrms.size() > 1) {
				log.error("Multiple credentials for credentialId: {}", credentialId);
			}
			this.prettyJson.log(credentialOrms);
			final CredentialOrm credentialOrm = credentialOrms.getFirst();
			final UserIdentityOrm userIdentityOrm = credentialOrm.userIdentity();
			this.prettyJson.log(userIdentityOrm);

			final String    username   = userIdentityOrm.username();
			final ByteArray userHandle = new ByteArray(userIdentityOrm.userHandle());

			final AssertionResult authenticationResult = this.relyingParty.finishAssertion(
				FinishAssertionOptions.builder()
			        .request(
		        		AssertionRequest.builder()
			        		.publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions)
			        		.username(username)
			        		.userHandle(userHandle)
			        		.build()
	        		)
			        .response(publicKeyCredential)
			        .build()
			);
			this.prettyJson.log(authenticationResult);

			final RegisteredCredential registeredCredential = authenticationResult.getCredential();
			this.prettyJson.log(registeredCredential);

			final AuthenticationFinishServer authenticationFinishServer = AuthenticationFinishServer.builder().registeredCredential(registeredCredential).build();
			this.prettyJson.log(authenticationFinishServer);

			return authenticationFinishServer;
		} catch (Exception e) {
			log.info("Finish authentication exception", e);
			if (e.getCause().getMessage().equals("Username not found for userHandle: Optional.empty")) {
				throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, e.getMessage(), e);
			}
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage(), e);
		}
	}

	private PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> cleanAndDecode(final String publicKeyCredentialJson) throws JsonProcessingException {
		log.info("publicKeyCredentialJson: {}", publicKeyCredentialJson);

		// decode into Map format
		final Map<String, Map<String, Object>> publicKeyCredentialMap = this.objectMapper.readValue(publicKeyCredentialJson, Map.class);

		// remove client-side data not supported by the server-side implementation of PublicKeyCredential
//		final Map<String, Object> publicKeyCredentialResponseMap = publicKeyCredentialMap.get("response");
//		final Object authenticatorData  = publicKeyCredentialResponseMap.remove("authenticatorData");
//		final Object publicKey          = publicKeyCredentialResponseMap.remove("publicKey");
//		final Object publicKeyAlgorithm = publicKeyCredentialResponseMap.remove("publicKeyAlgorithm");
//		log.debug("Removed unsupported client-side data response.authenticatorData: {}", authenticatorData);
//		log.debug("Removed unsupported client-side data response.publicKey: {}", publicKey);
//		log.debug("Removed unsupported client-side data response.publicKeyAlgorithm: {}", publicKeyAlgorithm);

		// convert remaining client-side data to server-side PublicKeyCredential
		final TypeReference<PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>> valueTypeRef = new TypeReference<>() {/*empty block*/};
		final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> publicKeyCredential = this.objectMapper.convertValue(publicKeyCredentialMap, valueTypeRef);
		this.prettyJson.log(publicKeyCredential);

		return publicKeyCredential;
	}
}
