package com.github.justincranford.springs.persistenceorm.sessions.json.serdes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.MissingNode;

@SuppressWarnings({"resource"})
public class UsernamePasswordAuthenticationTokenDeserializer extends JsonDeserializer<UsernamePasswordAuthenticationToken> {
	@Override
	public UsernamePasswordAuthenticationToken deserialize(final JsonParser jp, final DeserializationContext ctxt) throws IOException {
		final ObjectMapper mapper   = (ObjectMapper) jp.getCodec();
		final JsonNode     jsonNode = mapper.readTree(jp);

		final Object                 principal     = getPrincipal(readJsonNode(jsonNode, "principal"), mapper);
		final Object                 credentials   = getCredentials(readJsonNode(jsonNode, "credentials"));
		final List<GrantedAuthority> authorities   = parseAuthorities(jsonNode);
		final Boolean                authenticated = getAuthenticated(readJsonNode(jsonNode, "authenticated"));
		final Object                 details       = getDetails(readJsonNode(jsonNode, "details"), mapper);

		final UsernamePasswordAuthenticationToken token = authenticated
				? UsernamePasswordAuthenticationToken.authenticated(principal, credentials, authorities)
				: UsernamePasswordAuthenticationToken.unauthenticated(principal, credentials);
		token.setDetails(details);
		return token;
	}

	private static JsonNode readJsonNode(final JsonNode jsonNode, final String field) {
		return jsonNode.has(field) ? jsonNode.get(field) : MissingNode.getInstance();
	}

	private static Object getCredentials(final JsonNode credentialsNode) {
		if (credentialsNode.isNull() || credentialsNode.isMissingNode()) {
			return null;
		}
		return credentialsNode.asText();
	}

	private static Object getPrincipal(final JsonNode principalNode, final ObjectMapper mapper) throws IOException {
		if (principalNode.isObject()) {
			return mapper.readValue(principalNode.traverse(mapper), Object.class);
		}
		return principalNode.asText();
	}

	private static List<GrantedAuthority> parseAuthorities(final JsonNode authoritiesNode) {
		final List<GrantedAuthority> authorities = new ArrayList<>();

		// Handle case where 'authorities' is wrapped in an UnmodifiableRandomAccessList (i.e., an array inside an array)
		if (authoritiesNode != null && authoritiesNode.isArray()) {
			// The first element contains the actual authorities
			final JsonNode authorityListNode = authoritiesNode.get(1);
			// Get the list from inside the UnmodifiableRandomAccessList
			if (authorityListNode != null && authorityListNode.isArray()) {
				// Loop through the array and extract SimpleGrantedAuthority objects
				for (final JsonNode authorityNode : authorityListNode) {
					if (authorityNode != null && authorityNode.has("authority")) {
						final String authority = authorityNode.get("authority").asText();
						if (authority != null) {
							authorities.add(new SimpleGrantedAuthority(authority));
						}
					}
				}
			}
		}
		return authorities;
	}

	private static boolean getAuthenticated(final JsonNode authenticatedNode) {
		return authenticatedNode.asBoolean();
	}

	private static Object getDetails(final JsonNode detailsNode, final ObjectMapper mapper) throws IOException {
		if (detailsNode.isNull() || detailsNode.isMissingNode()) {
			return null;
		}
		return mapper.readValue(detailsNode.toString(), Object.class);
	}
}
