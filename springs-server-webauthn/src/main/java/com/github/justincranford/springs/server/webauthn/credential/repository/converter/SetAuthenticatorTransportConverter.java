package com.github.justincranford.springs.server.webauthn.credential.repository.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.converter.JsonConverter;
import com.yubico.webauthn.data.AuthenticatorTransport;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Converter
public class SetAuthenticatorTransportConverter extends JsonConverter<Set<AuthenticatorTransport>> {
    public SetAuthenticatorTransportConverter(final ObjectMapper objectMapper) {
        super(
            objectMapper, new TypeReference<>() {/*empty block*/
            }
        );
    }
}
