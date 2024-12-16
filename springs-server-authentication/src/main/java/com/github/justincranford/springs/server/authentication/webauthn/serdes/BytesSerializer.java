package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import org.springframework.security.web.webauthn.api.Bytes;

import java.io.IOException;

public class BytesSerializer extends JsonSerializer<Bytes> {
    @Override
    public void serialize(Bytes value, JsonGenerator gen, SerializerProvider serializers) throws IOException {
        gen.writeBinary(value.getBytes());
    }
}
