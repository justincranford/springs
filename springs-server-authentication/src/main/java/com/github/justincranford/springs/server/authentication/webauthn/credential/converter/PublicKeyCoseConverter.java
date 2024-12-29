package com.github.justincranford.springs.server.authentication.webauthn.credential.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCose;

@Converter
public class PublicKeyCoseConverter implements AttributeConverter<PublicKeyCose, byte[]> {
	@Override
	public byte[] convertToDatabaseColumn(final PublicKeyCose publicKeyCose) {
		return publicKeyCose.getBytes();
	}

	@Override
	public PublicKeyCose convertToEntityAttribute(final byte[] bytes) {
		return new ImmutablePublicKeyCose(bytes);
	}
}
