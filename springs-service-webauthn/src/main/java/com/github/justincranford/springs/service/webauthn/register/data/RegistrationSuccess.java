package com.github.justincranford.springs.service.webauthn.register.data;

import java.io.IOException;
import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.justincranford.springs.service.webauthn.credential.data.AttestationCertInfo;
import com.github.justincranford.springs.service.webauthn.util.AuthDataSerializer;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;

//@Accessors(fluent = true)
@AllArgsConstructor
@NoArgsConstructor
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString
@EqualsAndHashCode
@Builder(toBuilder=true)
@Slf4j
@SuppressWarnings({"nls", "hiding"})
public class RegistrationSuccess {
	@Builder.Default
	private boolean success = true;
	private RegistrationRequest request;
	private RegistrationResponse response;
	private RegisteredCredential registration;
	private boolean attestationTrusted;
	private Optional<AttestationCertInfo> attestationCert;

	@JsonSerialize(using = AuthDataSerializer.class)
	private AuthenticatorData authData;

	private String username;
	private String sessionToken;

	@JsonCreator
	public RegistrationSuccess(RegistrationRequest request, RegistrationResponse response, RegisteredCredential registration, boolean attestationTrusted, String sessionToken) {
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
