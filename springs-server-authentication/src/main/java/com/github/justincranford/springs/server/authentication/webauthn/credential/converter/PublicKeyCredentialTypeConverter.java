package com.github.justincranford.springs.server.authentication.webauthn.credential.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;

@Converter
public class PublicKeyCredentialTypeConverter implements AttributeConverter<PublicKeyCredentialType, String> {
	@Override
	public String convertToDatabaseColumn(final PublicKeyCredentialType publicKeyCredentialType) {
		return publicKeyCredentialType.getValue();
	}

	@Override
	public PublicKeyCredentialType convertToEntityAttribute(final String publicKeyCredentialType) {
		return PublicKeyCredentialType.valueOf(publicKeyCredentialType);
	}
}
