package com.github.justincranford.springs.service.webauthn.register.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

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
public class RegistrationStartServer {
	private String sessionToken;
	private PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;
}
