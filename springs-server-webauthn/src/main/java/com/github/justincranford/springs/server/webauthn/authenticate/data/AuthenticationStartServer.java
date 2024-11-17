package com.github.justincranford.springs.server.webauthn.authenticate.data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

//@Accessors(fluent = true)
@AllArgsConstructor
@Getter(onMethod = @__(@JsonProperty))
@Setter
@ToString
@EqualsAndHashCode
@Builder(toBuilder = true)
public class AuthenticationStartServer {
    private String sessionToken;
    private PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;
}
