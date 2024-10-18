package com.github.justincranford.springs.service.webauthn.register.repository;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.converter.JsonConverterDelegate;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

import jakarta.persistence.Converter;

// TODO Use this in RegistrationOrm
@Component
@Converter
public class PublicKeyCredentialCreationOptionsConverter extends JsonConverterDelegate<PublicKeyCredentialCreationOptions> {
    public PublicKeyCredentialCreationOptionsConverter(final ObjectMapper objectMapper) {
		super(objectMapper, new TypeReference<PublicKeyCredentialCreationOptions>() {/*empty block*/});
	}
}