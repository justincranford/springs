package com.github.justincranford.springs.server.webauthn.authenticate.repository;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.converter.JsonConverter;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;

import jakarta.persistence.Converter;

@Component
@Converter
public class PublicKeyCredentialRequestOptionsConverter extends JsonConverter<PublicKeyCredentialRequestOptions> {
    public PublicKeyCredentialRequestOptionsConverter(final ObjectMapper objectMapper) {
		super(objectMapper, new TypeReference<PublicKeyCredentialRequestOptions>() {/*empty block*/});
	}
}