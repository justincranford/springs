package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.List;
import java.util.Set;

public final class SerializationMain {
    private SerializationMain() { }

    public static void main(String[] args) throws Exception {
        final ObjectMapper objectMapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .registerModule(new Jdk8Module())
            .setSerializationInclusion(JsonInclude.Include.NON_EMPTY)
            .enable(JsonParser.Feature.INCLUDE_SOURCE_IN_LOCATION)
            .configure(SerializationFeature.INDENT_OUTPUT, true)
            .configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false)
            .configure(SerializationFeature.WRITE_DURATIONS_AS_TIMESTAMPS, false)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
            ;

        final SimpleModule webauthnSerdesModule = new SimpleModule();
        objectMapper.registerModule(webauthnSerdesModule);

        objectMapper.addMixIn(PublicKeyCredentialRequestOptions.class, WebauthnPublicKeyCredentialRequestOptionsMixIn.class);

        objectMapper.addMixIn(PublicKeyCredentialCreationOptions.class, WebauthnPublicKeyCredentialCreationOptionsMixIn.class);
        objectMapper.addMixIn(UserVerificationRequirement.class, UserVerificationRequirementMixIn.class);
        objectMapper.addMixIn(ImmutableAuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
        objectMapper.addMixIn(AuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
        objectMapper.addMixIn(AuthenticationExtensionsClientInput.class, AuthenticationExtensionsClientInputMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialDescriptor.class, PublicKeyCredentialDescriptorMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixIn.class);
        objectMapper.addMixIn(AuthenticatorTransport.class, AuthenticatorTransportMixIn.class);
        objectMapper.addMixIn(CredProtectAuthenticationExtensionsClientInput.class, CredProtectAuthenticationExtensionsClientInputMixIn.class);
        objectMapper.addMixIn(CredProtect.class, CredProtectMixIn.class);
        objectMapper.addMixIn(Bytes.class, WebauthnBytesMixIn.class);


        final Bytes bytes = new Bytes(new byte[] {1, 2, 3, 4, 5, 6 });
        final String serializedBytes = objectMapper.writeValueAsString(bytes);
        System.out.println("Serialized  Bytes: " + serializedBytes);
        final Bytes deserializedBytes = objectMapper.readValue(serializedBytes, Bytes.class);
        System.out.println("Deserialized Bytes: " + deserializedBytes + "\n");

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
            .extensions(new ImmutableAuthenticationExtensionsClientInputs(
                new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true))
            ))
            .build();
        final String serializedPublicKeyCredentialRequestOptions = objectMapper.writeValueAsString(publicKeyCredentialRequestOptions);
        System.out.println("Serialized  publicKeyCredentialRequestOptions: " + serializedPublicKeyCredentialRequestOptions);
        final PublicKeyCredentialRequestOptions deserializedPublicKeyCredentialRequestOptions = objectMapper.readValue(serializedPublicKeyCredentialRequestOptions, PublicKeyCredentialRequestOptions.class);
        System.out.println("Deserialized publicKeyCredentialRequestOptions: " + deserializedPublicKeyCredentialRequestOptions + "\n");
    }

    /** @see org.springframework.security.web.webauthn.api.Bytes */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class WebauthnBytesMixIn {
        @JsonCreator
        public WebauthnBytesMixIn(
            @JsonProperty("bytes") byte[] bytes
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class WebauthnPublicKeyCredentialCreationOptionsMixIn {
        @JsonCreator
        public WebauthnPublicKeyCredentialCreationOptionsMixIn(
            @JsonProperty("challenge") Bytes challenge,
            @JsonProperty("timeout") Duration timeout,
            @JsonProperty("rpId") String rpId,
            @JsonProperty("allowCredentials") List<PublicKeyCredentialDescriptor> allowCredentials,
            @JsonProperty("userVerification") UserVerificationRequirement userVerification,
            @JsonProperty("extensions") AuthenticationExtensionsClientInputs extensions
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class WebauthnPublicKeyCredentialRequestOptionsMixIn {
        @JsonCreator
        public WebauthnPublicKeyCredentialRequestOptionsMixIn(
            @JsonProperty("challenge") Bytes challenge,
            @JsonProperty("timeout") Duration timeout,
            @JsonProperty("rpId") String rpId,
            @JsonProperty("allowCredentials") List<PublicKeyCredentialDescriptor> allowCredentials,
            @JsonProperty("userVerification") UserVerificationRequirement userVerification,
            @JsonProperty("extensions") AuthenticationExtensionsClientInputs extensions
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.UserVerificationRequirement */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class UserVerificationRequirementMixIn {
        @JsonCreator
        public UserVerificationRequirementMixIn(
            @JsonProperty("value") String value
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class AuthenticationExtensionsClientInputsMixIn {
        @JsonCreator
        public AuthenticationExtensionsClientInputsMixIn(
            @JsonProperty("inputs") List<? extends AuthenticationExtensionsClientInput> inputs
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class AuthenticationExtensionsClientInputMixIn {
        @JsonCreator
        public AuthenticationExtensionsClientInputMixIn(
            @JsonProperty("extensionId") String extensionId,
            @JsonProperty("input") String input
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class PublicKeyCredentialDescriptorMixIn {
        @JsonCreator
        public PublicKeyCredentialDescriptorMixIn(
            @JsonProperty("type") PublicKeyCredentialType type,
            @JsonProperty("id") Bytes id,
            @JsonProperty("transports") Set<AuthenticatorTransport> transports
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.PublicKeyCredentialType */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class PublicKeyCredentialTypeMixIn {
        @JsonCreator
        public PublicKeyCredentialTypeMixIn(
            @JsonProperty("value") String value
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.AuthenticatorTransport */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class AuthenticatorTransportMixIn {
        @JsonCreator
        public AuthenticatorTransportMixIn(
            @JsonProperty("value") String value
        ) { }
    }

    /** @see org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class CredProtectAuthenticationExtensionsClientInputMixIn {
        @JsonCreator
        public CredProtectAuthenticationExtensionsClientInputMixIn(
            @JsonProperty("input") CredProtect input
        ) { }
        @JsonIgnore public abstract String getExtensionId();
    }

    /** @see org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect */
    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@class")
    public static abstract class CredProtectMixIn {
        @JsonCreator
        public CredProtectMixIn(
            @JsonProperty("credProtectionPolicy") ProtectionPolicy credProtectionPolicy,
            @JsonProperty("enforceCredentialProtectionPolicy") boolean enforceCredentialProtectionPolicy
        ) { }
    }
}
