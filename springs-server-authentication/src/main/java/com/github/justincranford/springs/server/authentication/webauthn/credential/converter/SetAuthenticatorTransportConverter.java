package com.github.justincranford.springs.server.authentication.webauthn.credential.converter;

import com.github.justincranford.springs.util.basic.StringUtil;
import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;

import java.util.Set;
import java.util.stream.Collectors;

@Converter
public class SetAuthenticatorTransportConverter implements AttributeConverter<Set<AuthenticatorTransport>, String> {
	@Override
	public String convertToDatabaseColumn(final Set<AuthenticatorTransport> authenticatorTransports) {
		return authenticatorTransports.stream().map(AuthenticatorTransport::getValue).collect(Collectors.joining(","));
	}

	@Override
	public Set<AuthenticatorTransport> convertToEntityAttribute(final String authenticatorTransports) {
		return StringUtil.split(authenticatorTransports, ",").stream().map(AuthenticatorTransport::valueOf).collect(Collectors.toSet());
	}
}
