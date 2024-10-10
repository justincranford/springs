package com.github.justincranford.springs.service.webauthn.register.data;

import java.io.IOException;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.justincranford.springs.service.webauthn.credential.data.AttestationCertInfo;
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
//	@Accessors(fluent = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
@ToString
@EqualsAndHashCode(callSuper = false)
@Slf4j
@SuppressWarnings({"nls", "hiding"})
public class SuccessfulRegistrationResult {
	private final boolean success = true;
	private final RegistrationRequest request;
	private final RegistrationResponse response;
	private final RegisteredCredential registration;
	private final boolean attestationTrusted;
	private final Optional<AttestationCertInfo> attestationCert;

	@JsonSerialize(using = AuthDataSerializer.class)
	private final AuthenticatorData authData;

	private final String username;
	private final String sessionToken;

	public SuccessfulRegistrationResult(RegistrationRequest request, RegistrationResponse response, RegisteredCredential registration, boolean attestationTrusted, String sessionToken) {
		this.request = request;
		this.response = response;
		this.registration = registration;
		this.attestationTrusted = attestationTrusted;
		this.attestationCert = Optional
			.ofNullable(
				response.getCredential().getResponse().getAttestation().getAttestationStatement().get("x5c")
			)
			.map(certs -> certs.get(0)).flatMap((JsonNode certDer) -> {
				try {
					return Optional.of(new ByteArray(certDer.binaryValue()));
				} catch (IOException e) {
					log.error("Failed to get binary value from x5c element: {}", certDer, e);
					return Optional.empty();
				}
			})
			.map(AttestationCertInfo::new);
		this.authData = response.getCredential().getResponse().getParsedAuthenticatorData();
		this.username = request.getUsername();
		this.sessionToken = sessionToken;
	}
}
