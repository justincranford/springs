package com.github.justincranford.springs.service.webauthn.authenticate.data;

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

import jakarta.validation.constraints.NotNull;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;

@RequiredArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter
//	@Accessors(fluent = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder
@SuppressWarnings({"hiding"})
public class AuthenticationRequest {
	private final boolean success = true;
	private final String requestId;
	private final AssertionRequest request;
	private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
	private final Optional<String> username;

	public AuthenticationRequest(
		@NotNull String requestId,
		@NotNull AssertionRequest request
	) {
		this.requestId = requestId;
		this.request = request;
		this.publicKeyCredentialRequestOptions = request.getPublicKeyCredentialRequestOptions();
		this.username = request.getUsername();
	}
}
