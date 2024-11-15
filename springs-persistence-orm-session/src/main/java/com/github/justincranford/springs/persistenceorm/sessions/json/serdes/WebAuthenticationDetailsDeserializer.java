package com.github.justincranford.springs.persistenceorm.sessions.json.serdes;

import java.io.IOException;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;

/**
 * @see AbstractAuthenticationToken#getDetails()
 * <p>
 * Default concrete class is:
 * @see WebAuthenticationDetails
 */
public class WebAuthenticationDetailsDeserializer extends StdDeserializer<WebAuthenticationDetails> {
	private static final long serialVersionUID = 1L;

	public WebAuthenticationDetailsDeserializer() {
		super(WebAuthenticationDetails.class);
	}

	@Override
	public WebAuthenticationDetails deserialize(final JsonParser p, final DeserializationContext ctxt) throws IOException {
		final JsonNode node = p.getCodec().readTree(p);
		final String remoteAddress = node.has("remoteAddress") ? node.get("remoteAddress").asText() : null;
		final String sessionId = node.has("sessionId") ? node.get("sessionId").asText() : null;
		return new WebAuthenticationDetails(remoteAddress, sessionId);
	}
}
