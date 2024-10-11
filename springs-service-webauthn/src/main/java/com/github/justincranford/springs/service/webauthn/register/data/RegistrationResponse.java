package com.github.justincranford.springs.service.webauthn.register.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

//@Accessors(fluent = true)
@AllArgsConstructor(onConstructor = @__(@JsonCreator))
@NoArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder(toBuilder=true)
public class RegistrationResponse {
	private PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> credential;
	private String sessionToken;
}
