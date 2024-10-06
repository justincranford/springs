package com.github.justincranford.springs.service.webauthn.register.data;

import java.util.Collection;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.justincranford.springs.service.webauthn.register.util.AuthDataSerializer;
import com.github.justincranford.springs.service.webauthn.rp.repository.CredentialOrm;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import lombok.ToString;

@Getter(onMethod = @__(@JsonProperty))
@Setter
//	@Accessors(fluent = true)
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@SuppressWarnings({"hiding"})
public final class SuccessfulAuthenticationResult {
	private final boolean success = true;
	private final AssertionRequestWrapper request;
	private final AssertionResponse response;
	private final Collection<CredentialOrm> registrations;

	@JsonSerialize(using = AuthDataSerializer.class)
	AuthenticatorData authData;

	private final String username;
	private final ByteArray sessionToken;

	public SuccessfulAuthenticationResult(AssertionRequestWrapper request, AssertionResponse response,
			Collection<CredentialOrm> registrations, String username, ByteArray sessionToken) {
		this(request, response, registrations, response.getCredential().getResponse().getParsedAuthenticatorData(),
				username, sessionToken);
	}

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//		@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	public class AssertionRequestWrapper {
		@NonNull
		private final ByteArray requestId;
		@NonNull
		private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
		@NonNull
		private final Optional<String> username;
		@NonNull
		@JsonIgnore
		private final transient com.yubico.webauthn.AssertionRequest request;

		public AssertionRequestWrapper(@NonNull ByteArray requestId,
				@NonNull com.yubico.webauthn.AssertionRequest request) {
			this.requestId = requestId;
			this.publicKeyCredentialRequestOptions = request.getPublicKeyCredentialRequestOptions();
			this.username = request.getUsername();
			this.request = request;
		}
	}

	@Getter(onMethod = @__(@JsonProperty))
	@Setter
//		@Accessors(fluent = true)
	@JsonInclude(JsonInclude.Include.NON_NULL)
	@ToString
	@EqualsAndHashCode(callSuper = false)
	@JsonIgnoreProperties({ "sessionToken" })
	public class AssertionResponse {
		private final ByteArray requestId;
		private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential;

		public AssertionResponse(@JsonProperty("requestId") ByteArray requestId,
				@JsonProperty("credential") PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> credential) {
			this.requestId = requestId;
			this.credential = credential;
		}
	}
}
