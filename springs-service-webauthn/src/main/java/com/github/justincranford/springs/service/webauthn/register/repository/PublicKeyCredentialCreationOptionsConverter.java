package com.github.justincranford.springs.service.webauthn.register.repository;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.converter.JsonConverter;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;

import jakarta.persistence.Converter;

@Component
@Converter
public class PublicKeyCredentialCreationOptionsConverter extends JsonConverter<PublicKeyCredentialCreationOptions> {
    public PublicKeyCredentialCreationOptionsConverter(final ObjectMapper objectMapper) {
		super(objectMapper, new TypeReference<PublicKeyCredentialCreationOptions>() {/*empty block*/});
	}
}