package com.github.justincranford.springs.service.webauthn.credential.repository.converter;

import java.util.Set;

import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.converter.JsonConverterDelegate;
import com.yubico.webauthn.data.AuthenticatorTransport;

import jakarta.persistence.Converter;

@Component
@Converter
public class SetAuthenticatorTransportConverter extends JsonConverterDelegate<Set<AuthenticatorTransport>> {
    public SetAuthenticatorTransportConverter(final ObjectMapper objectMapper) {
		super(objectMapper, new TypeReference<Set<AuthenticatorTransport>>() {/*empty block*/});
	}
}