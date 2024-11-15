package com.github.justincranford.springs.persistenceorm.sessions.json.serdes;

import java.io.IOException;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import com.github.justincranford.springs.persistenceorm.sessions.database.util.CustomGrantedAuthority;

public class CustomGrantedAuthorityDeserializer extends StdDeserializer<CustomGrantedAuthority> {
	private static final long serialVersionUID = 1L;

    public CustomGrantedAuthorityDeserializer() {
        super(CustomGrantedAuthority.class);
    }

    @Override
    public CustomGrantedAuthority deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
        JsonNode node = p.getCodec().readTree(p);
		final String authority = node.has("authority") ? node.get("authority").asText() : null;
        return new CustomGrantedAuthority(authority);
    }
}
