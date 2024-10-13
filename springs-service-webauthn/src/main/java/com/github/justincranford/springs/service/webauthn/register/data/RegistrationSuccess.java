package com.github.justincranford.springs.service.webauthn.register.data;

import java.util.Optional;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.github.justincranford.springs.service.webauthn.credential.data.AttestationCertInfo;
import com.github.justincranford.springs.service.webauthn.util.AuthDataSerializer;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorData;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

//@Accessors(fluent = true)
@AllArgsConstructor
@NoArgsConstructor
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString
@EqualsAndHashCode
@Builder(toBuilder=true)
public class RegistrationSuccess {
	private boolean success;
	private RegistrationRequest request;
	private RegistrationResponse response;
	private RegisteredCredential registration;
	private boolean attestationTrusted;
	private Optional<AttestationCertInfo> attestationCert;

	@JsonSerialize(using = AuthDataSerializer.class)
	private AuthenticatorData authData;

	private String username;
	private String sessionToken;
}
