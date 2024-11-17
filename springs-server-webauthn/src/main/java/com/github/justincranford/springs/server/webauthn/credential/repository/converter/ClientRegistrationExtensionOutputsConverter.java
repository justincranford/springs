package com.github.justincranford.springs.server.webauthn.credential.repository.converter;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.converter.JsonConverter;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import jakarta.persistence.Converter;
import org.springframework.stereotype.Component;

@Component
@Converter
public class ClientRegistrationExtensionOutputsConverter extends JsonConverter<ClientRegistrationExtensionOutputs> {
    public ClientRegistrationExtensionOutputsConverter(final ObjectMapper objectMapper) {
        super(
            objectMapper, new TypeReference<>() {/*empty block*/}
        );
    }
}
