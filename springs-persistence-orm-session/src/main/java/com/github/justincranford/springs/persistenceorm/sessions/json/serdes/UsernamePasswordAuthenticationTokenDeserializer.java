package com.github.justincranford.springs.persistenceorm.sessions.json.serdes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

@SuppressWarnings({"static-method", "resource"})
public class UsernamePasswordAuthenticationTokenDeserializer extends JsonDeserializer<UsernamePasswordAuthenticationToken> {
	@Override
	public UsernamePasswordAuthenticationToken deserialize(JsonParser jp, DeserializationContext ctxt) throws IOException {
		final ObjectMapper mapper   = (ObjectMapper) jp.getCodec();
		final JsonNode     jsonNode = mapper.readTree(jp);

		final Object                 principal     = getPrincipal(readJsonNode(jsonNode, "principal"), mapper);
		final Object                 credentials   = getCredentials(readJsonNode(jsonNode, "credentials"));
		final List<GrantedAuthority> authorities   = parseAuthorities(jsonNode);
		final Boolean                authenticated = getAuthenticated(readJsonNode(jsonNode, "authenticated"));
		final Object                 details       = getDetails(readJsonNode(jsonNode, "details"), mapper);

		final UsernamePasswordAuthenticationToken token = (!authenticated)
				? UsernamePasswordAuthenticationToken.unauthenticated(principal, credentials)
				: UsernamePasswordAuthenticationToken.authenticated(principal, credentials, authorities);
		token.setDetails(details);
		return token;
	}

	private JsonNode readJsonNode(JsonNode jsonNode, String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

	private Object getCredentials(JsonNode credentialsNode) {
		if (credentialsNode.isNull() || credentialsNode.isMissingNode()) {
			return null;
		}
		return credentialsNode.asText();
	}

	private Object getPrincipal(JsonNode principalNode, ObjectMapper mapper) throws IOException, JsonParseException, JsonMappingException {
		if (principalNode.isObject()) {
			return mapper.readValue(principalNode.traverse(mapper), Object.class);
		}
		return principalNode.asText();
	}

	private List<GrantedAuthority> parseAuthorities(JsonNode authoritiesNode) {
		final List<GrantedAuthority> authorities = new ArrayList<>();

		// Handle case where 'authorities' is wrapped in an UnmodifiableRandomAccessList (i.e., an array inside an array)
		if (authoritiesNode != null && authoritiesNode.isArray()) {
			// The first element contains the actual authorities
			JsonNode authorityListNode = authoritiesNode.get(1);
			// Get the list from inside the UnmodifiableRandomAccessList
			if (authorityListNode != null && authorityListNode.isArray()) {
				// Loop through the array and extract SimpleGrantedAuthority objects
				for (JsonNode authorityNode : authorityListNode) {
					if (authorityNode != null && authorityNode.has("authority")) {
						String authority = authorityNode.get("authority").asText();
						if (authority != null) {
							authorities.add(new SimpleGrantedAuthority(authority));
						}
					}
				}
			}
		}
		return authorities;
	}

	private boolean getAuthenticated(final JsonNode authenticatedNode) {
		return authenticatedNode.asBoolean();
	}

	private Object getDetails(JsonNode detailsNode, ObjectMapper mapper) throws JsonProcessingException, JsonMappingException {
		if (detailsNode.isNull() || detailsNode.isMissingNode()) {
			return null;
		}
		return mapper.readValue(detailsNode.toString(), Object.class);
	}
}
