package com.github.justincranford.springs.service.webauthn.authenticate.data;

import java.io.IOException;
import java.util.Collection;
import java.util.Optional;
import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.justincranford.springs.service.webauthn.credential.data.AttestationCertInfo;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.util.AuthDataSerializer;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter
//@Accessors(fluent = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@Slf4j
@SuppressWarnings({"nls", "hiding"})
public class AuthenticationSuccess {
	private final boolean success = true;
	private final AuthenticationRequest request;
	private final AuthenticationResponse response;
    private final Set<RegisteredCredential> registrations;

	@JsonSerialize(using = AuthDataSerializer.class)
	private final AuthenticatorData authData;

	private final String username;
	private final String sessionToken;

	public AuthenticationSuccess(
		AuthenticationRequest request,
		AuthenticationResponse response,
		Set<RegisteredCredential> registrations,
		String username,
		String sessionToken
	) {
		this.request = request;
		this.response = response;
		this.registrations = registrations;
		this.authData = response.getCredential().getResponse().getParsedAuthenticatorData();
		this.username = username;
		this.sessionToken = sessionToken;
	}
}
