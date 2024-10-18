package com.github.justincranford.springs.service.webauthn.credential.repository.converter;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.converter.JsonConverterDelegate;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;

import jakarta.persistence.Converter;

@Component
@Converter
public class ClientRegistrationExtensionOutputsConverter extends JsonConverterDelegate<ClientRegistrationExtensionOutputs> {
    public ClientRegistrationExtensionOutputsConverter(final ObjectMapper objectMapper) {
		super(objectMapper, new TypeReference<ClientRegistrationExtensionOutputs>() {/*empty block*/});
	}
}