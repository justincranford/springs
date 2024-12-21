package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Set;

@Slf4j
public class WebauthnSerdesIT extends AbstractIT {
    @Test
    void testSerdesBytes() throws JsonProcessingException {
        final Bytes bytes = Bytes.random();

        final String serialized = springSessionDefaultObjectMapper().writeValueAsString(bytes);
        log.info("Serialized: {}", serialized);

        final Bytes deserialized = springSessionDefaultObjectMapper().readValue(serialized, Bytes.class);
        log.info("Deserialized: {}\n", deserialized);
    }

    @Test
    void testSerdesPublicKeyCredentialCreationOptions() throws JsonProcessingException {
        final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions = PublicKeyCredentialCreationOptions.builder()
            .rp(PublicKeyCredentialRpEntity.builder().id("example.com").name("Example RP").build())
            .user(ImmutablePublicKeyCredentialUserEntity.builder().name("name").id(Bytes.random()).displayName("displayName").build())
            .challenge(Bytes.random())
            .pubKeyCredParams(List.of(PublicKeyCredentialParameters.ES384, PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.RS512))
            .timeout(Duration.ofSeconds(60))
            .excludeCredentials(Collections.singletonList(
                PublicKeyCredentialDescriptor.builder()
                    .id(Bytes.random())
                    .type(PublicKeyCredentialType.PUBLIC_KEY)
                    .transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
                    .build()
            ))
            .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                .userVerification(UserVerificationRequirement.PREFERRED)
                .residentKey(ResidentKeyRequirement.REQUIRED)
                .authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
                .build()
            )
            .attestation(AttestationConveyancePreference.DIRECT)
            .extensions(
                new ImmutableAuthenticationExtensionsClientInputs(new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true)))
            )
            .build();

        final String serialized = springSessionDefaultObjectMapper().writeValueAsString(publicKeyCredentialCreationOptions);
        log.info("Serialized: {}", serialized);

        final PublicKeyCredentialCreationOptions deserialized = springSessionDefaultObjectMapper().readValue(serialized, PublicKeyCredentialCreationOptions.class);
        log.info("Deserialized: {}\n", deserialized);
    }

    @Test
    void testSerdesPublicKeyCredentialRequestOptions() throws JsonProcessingException {
        final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions = PublicKeyCredentialRequestOptions.builder()
            .challenge(Bytes.random())
            .timeout(Duration.ofSeconds(60))
            .rpId("example.com")
            .allowCredentials(
                List.of(
                    PublicKeyCredentialDescriptor.builder()
                        .id(Bytes.random())
                        .type(PublicKeyCredentialType.PUBLIC_KEY)
                        .transports(Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID))
                        .build()
                )
            )
            .userVerification(UserVerificationRequirement.PREFERRED)
            .extensions(
                new ImmutableAuthenticationExtensionsClientInputs(
                    new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true))
                )
            )
            .build();

        final String serialized = springSessionDefaultObjectMapper().writeValueAsString(publicKeyCredentialRequestOptions);
        log.info("Serialized: {}", serialized);

        final PublicKeyCredentialRequestOptions deserialized = springSessionDefaultObjectMapper().readValue(serialized, PublicKeyCredentialRequestOptions.class);
        log.info("Deserialized: {}\n", deserialized);

    }
}
