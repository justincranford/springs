package com.github.justincranford.springs.server.authentication.webauthn.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.AttestationConveyancePreferenceMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.AuthenticationExtensionsClientInputMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.AuthenticationExtensionsClientInputsMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.AuthenticatorAttachmentMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.AuthenticatorSelectionCriteriaMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.AuthenticatorTransportMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.COSEAlgorithmIdentifierMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.CredProtectAuthenticationExtensionsClientInputMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.CredProtectMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.PublicKeyCredentialDescriptorMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.PublicKeyCredentialParametersMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.PublicKeyCredentialRpEntityMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.PublicKeyCredentialTypeMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.PublicKeyCredentialUserEntityMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.ResidentKeyRequirementMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.UserVerificationRequirementMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.WebauthnBytesMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.WebauthnPublicKeyCredentialCreationOptionsMixIn;
import com.github.justincranford.springs.server.authentication.webauthn.serdes.WebauthnMixins.WebauthnPublicKeyCredentialRequestOptionsMixIn;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.AuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.COSEAlgorithmIdentifier;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

@Configuration
@Slf4j
@SuppressWarnings({"unused"})
public class SpringsServerAuthenticationWebauthnConfiguration {
    /** @see com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration#objectMapper */
    @Autowired
    private ObjectMapper objectMapper;

    @Qualifier("springSessionDefaultObjectMapper")
    @Autowired
    private ObjectMapper springSessionDefaultObjectMapper;

    @PostConstruct
    public void postConstruct() {
        updateObjectMapper(this.objectMapper);
        updateObjectMapper(this.springSessionDefaultObjectMapper);
    }

    public static void updateObjectMapper(final ObjectMapper objectMapper) {
//        objectMapper.addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class);

        objectMapper.addMixIn(Bytes.class, WebauthnBytesMixIn.class);

        objectMapper.addMixIn(PublicKeyCredentialCreationOptions.class, WebauthnPublicKeyCredentialCreationOptionsMixIn.class);
        objectMapper.addMixIn(ImmutablePublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialUserEntity.class, PublicKeyCredentialUserEntityMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialRpEntity.class, PublicKeyCredentialRpEntityMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialParameters.class, PublicKeyCredentialParametersMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialType.class, PublicKeyCredentialTypeMixIn.class);
        objectMapper.addMixIn(COSEAlgorithmIdentifier.class, COSEAlgorithmIdentifierMixIn.class);
        objectMapper.addMixIn(AuthenticatorSelectionCriteria.class, AuthenticatorSelectionCriteriaMixIn.class);
        objectMapper.addMixIn(AttestationConveyancePreference.class, AttestationConveyancePreferenceMixIn.class);
        objectMapper.addMixIn(AuthenticatorAttachment.class, AuthenticatorAttachmentMixIn.class);
        objectMapper.addMixIn(ResidentKeyRequirement.class, ResidentKeyRequirementMixIn.class);
        objectMapper.addMixIn(UserVerificationRequirement.class, UserVerificationRequirementMixIn.class);

        objectMapper.addMixIn(PublicKeyCredentialRequestOptions.class, WebauthnPublicKeyCredentialRequestOptionsMixIn.class);
        objectMapper.addMixIn(ImmutableAuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
        objectMapper.addMixIn(AuthenticationExtensionsClientInputs.class, AuthenticationExtensionsClientInputsMixIn.class);
        objectMapper.addMixIn(AuthenticationExtensionsClientInput.class, AuthenticationExtensionsClientInputMixIn.class);
        objectMapper.addMixIn(PublicKeyCredentialDescriptor.class, PublicKeyCredentialDescriptorMixIn.class);
        objectMapper.addMixIn(AuthenticatorTransport.class, AuthenticatorTransportMixIn.class);
        objectMapper.addMixIn(CredProtectAuthenticationExtensionsClientInput.class, CredProtectAuthenticationExtensionsClientInputMixIn.class);
        objectMapper.addMixIn(CredProtect.class, CredProtectMixIn.class);

        log.info("Registered Modules:\n{}", objectMapper.getRegisteredModuleIds());
    }
}
