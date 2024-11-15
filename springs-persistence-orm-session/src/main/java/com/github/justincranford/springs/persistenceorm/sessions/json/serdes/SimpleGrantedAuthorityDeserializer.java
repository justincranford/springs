package com.github.justincranford.springs.persistenceorm.sessions.json.serdes;

import java.io.IOException;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.database.util.CustomGrantedAuthority;

public class SimpleGrantedAuthorityDeserializer extends StdDeserializer<SimpleGrantedAuthority> {
	private static final long serialVersionUID = 1L;

    public SimpleGrantedAuthorityDeserializer() {
        super(CustomGrantedAuthority.class);
    }

    @Override
    public SimpleGrantedAuthority deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);
		final String authority = node.has("authority") ? node.get("authority").asText() : null;
        return new SimpleGrantedAuthority(authority);
    }
}
