package com.github.justincranford.springs.server.authentication.webauthn.serdes;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import org.springframework.security.web.webauthn.api.Bytes;

import java.io.IOException;

public class BytesDeserializer extends JsonDeserializer<Bytes> {
    @Override
    public Bytes deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        byte[] data = p.getBinaryValue();
        return new Bytes(data);
    }
}
