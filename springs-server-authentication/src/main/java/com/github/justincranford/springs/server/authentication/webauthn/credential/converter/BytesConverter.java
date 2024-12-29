package com.github.justincranford.springs.server.authentication.webauthn.credential.converter;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.web.webauthn.api.Bytes;

@Converter
public class BytesConverter implements AttributeConverter<Bytes, byte[]> {
	@Override
	public byte[] convertToDatabaseColumn(final Bytes bytes) {
		return bytes.getBytes();
	}

	@Override
	public Bytes convertToEntityAttribute(final byte[] bytes) {
		return new Bytes(bytes);
	}
}
