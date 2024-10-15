package com.github.justincranford.springs.service.webauthn.credential.repository.converter;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import com.yubico.webauthn.data.AuthenticatorTransport;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

@Converter
@SuppressWarnings("nls")
public class SetAuthenticatorTransportConverter implements AttributeConverter<Set<AuthenticatorTransport>, String> {
    @Override
    public String convertToDatabaseColumn(Set<AuthenticatorTransport> unencodedTransports) {
        return unencodedTransports != null ? unencodedTransports.stream()
            .map(AuthenticatorTransport::getId)
            .collect(Collectors.joining(",")) : "";
    }

	@Override
    public Set<AuthenticatorTransport> convertToEntityAttribute(String encodedTransports) {
        return encodedTransports != null && !encodedTransports.isEmpty() ? 
            Arrays.stream(encodedTransports.split(","))
            .map(AuthenticatorTransport::valueOf)
            .collect(Collectors.toSet()) : Set.of();
    }
}
