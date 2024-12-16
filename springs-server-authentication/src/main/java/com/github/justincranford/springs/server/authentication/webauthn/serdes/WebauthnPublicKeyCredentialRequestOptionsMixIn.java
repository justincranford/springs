package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.List;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class WebauthnPublicKeyCredentialRequestOptionsMixIn {
    /** @see org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions */
    @JsonCreator
    public WebauthnPublicKeyCredentialRequestOptionsMixIn(
        @JsonProperty("challenge") Bytes challenge,
        @JsonProperty("timeout") Duration timeout,
        @JsonProperty("rpId") String rpId,
        @JsonProperty("allowCredentials") List<PublicKeyCredentialDescriptor> allowCredentials,
        @JsonProperty("userVerification") UserVerificationRequirement userVerification,
        @JsonProperty("extensions") AuthenticationExtensionsClientInputs extensions
    ) {
        // No implementation needed, just the annotations
    }
}
