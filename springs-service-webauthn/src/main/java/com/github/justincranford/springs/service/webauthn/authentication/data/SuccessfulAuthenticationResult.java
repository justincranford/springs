package com.github.justincranford.springs.service.webauthn.authentication.data;

import java.io.IOException;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.justincranford.springs.service.webauthn.register.data.AttestationCertInfo;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;
import com.github.justincranford.springs.service.webauthn.util.AuthDataSerializer;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

@Getter(onMethod = @__(@JsonProperty))
@Setter
//	@Accessors(fluent = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@Slf4j
@SuppressWarnings({"nls", "hiding"})
public class SuccessfulAuthenticationResult {
	final boolean success = true;
	RegistrationRequest request;
	RegistrationResponse response;
	RegisteredCredential registration;
	boolean attestationTrusted;
	Optional<AttestationCertInfo> attestationCert;

	@JsonSerialize(using = AuthDataSerializer.class)
	AuthenticatorData authData;

	String username;
	String sessionToken;

	public SuccessfulAuthenticationResult(RegistrationRequest request, RegistrationResponse response,
			RegisteredCredential registration, boolean attestationTrusted, String sessionToken) {
		this.request = request;
		this.response = response;
		this.registration = registration;
		this.attestationTrusted = attestationTrusted;
		this.attestationCert = Optional
				.ofNullable(
						response.getCredential().getResponse().getAttestation().getAttestationStatement().get("x5c"))
				.map(certs -> certs.get(0)).flatMap((JsonNode certDer) -> {
					try {
						return Optional.of(new ByteArray(certDer.binaryValue()));
					} catch (IOException e) {
						log.error("Failed to get binary value from x5c element: {}", certDer, e);
						return Optional.empty();
					}
				}).map(AttestationCertInfo::new);
		this.authData = response.getCredential().getResponse().getParsedAuthenticatorData();
		this.username = request.getUsername();
		this.sessionToken = sessionToken;
	}
}
