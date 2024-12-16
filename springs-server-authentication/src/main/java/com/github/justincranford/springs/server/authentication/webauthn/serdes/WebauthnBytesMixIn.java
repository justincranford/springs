package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import org.springframework.security.web.webauthn.api.Bytes;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
public abstract class WebauthnBytesMixIn {
    /** @see org.springframework.security.web.webauthn.api.Bytes */
    @JsonCreator
    public WebauthnBytesMixIn(
        @JsonProperty("bytes") Bytes bytes
    ) {
        // No implementation needed, just the annotations
    }
}
