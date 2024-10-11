package com.github.justincranford.springs.service.webauthn.authenticate.data;

import java.util.Set;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
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
@AllArgsConstructor(onConstructor = @__(@JsonCreator))
@NoArgsConstructor(onConstructor = @__(@JsonCreator))
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString
@EqualsAndHashCode(callSuper = false)
@Builder(toBuilder=true)
public class AuthenticationSuccess {
	@Builder.Default
	private boolean success = true;
	private AuthenticationRequest request;
	private AuthenticationResponse response;
    private Set<RegisteredCredential> registrations;
	@JsonSerialize(using = AuthDataSerializer.class)
	private AuthenticatorData authData;
	private String username;
	private String sessionToken;
}
