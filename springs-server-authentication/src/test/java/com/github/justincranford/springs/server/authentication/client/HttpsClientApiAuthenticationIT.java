package com.github.justincranford.springs.server.authentication.client;

import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.RepeatedTest;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

@Slf4j
public class HttpsClientApiAuthenticationIT extends AbstractIT {
	private static final int REPEATS = 1;

	@Nested
	public class HttpsLoginRedirectWhenUnauthenticated {
		@RepeatedTest(REPEATS)
		void sTls() {
			attemptUnauthenticatedHttpGet(stlsRestTemplate());
		}
		@RepeatedTest(REPEATS)
		void mTls() {
			attemptUnauthenticatedHttpGet(mtlsRestTemplate());
		}
	}

	@Nested
	public class HttpsLoginClientName {
		@Nested
		public class Success {
			@RepeatedTest(REPEATS)
			void sTlsCheckStatus() {
				attemptLoginClientName(stlsRestTemplate(), true);
			}
			@RepeatedTest(REPEATS)
			void mTlsCheckStatus() {
				attemptLoginClientName(mtlsRestTemplate(), true);
			}
			@RepeatedTest(REPEATS)
			void sTlsRequestJwt() throws Exception {
				attemptRequestJwt(stlsRestTemplate(), true);
			}
			@RepeatedTest(REPEATS)
			void mTlsRequestJwt() throws Exception {
				attemptRequestJwt(mtlsRestTemplate(), true);
			}
		}

		@Nested
		public class Failure {
			@RepeatedTest(REPEATS)
			void sTlsCheckStatus() {
				attemptLoginClientName(stlsRestTemplate(), false);
			}
			@RepeatedTest(REPEATS)
			void mTlsCheckStatus() {
				attemptLoginClientName(mtlsRestTemplate(), false);
			}
			@RepeatedTest(REPEATS)
			void sTlsRequestJwt() throws Exception {
				attemptRequestJwt(stlsRestTemplate(), false);
			}
			@RepeatedTest(REPEATS)
			void mTlsRequestJwt() throws Exception {
				attemptRequestJwt(mtlsRestTemplate(), false);
			}
		}
	}

	private void attemptUnauthenticatedHttpGet(final RestTemplate httpsRestTemplate) {
		final String response = RestTemplateUtil.plainGet(httpsRestTemplate, httpsBaseUrl() + "/api/v1/authenticate/status", null, String.class);
		assertThat(response).contains("Authenticated as anonymous");
	}

	private void attemptLoginClientName(final RestTemplate httpsRestTemplate, final boolean assertLoginSuccess) {
		final List<SpringsPersistenceOrmClientsClientProperties.Client> clients = springsPersistenceOrmClientsClientProperties().getClient();
        Assertions.assertFalse(clients.isEmpty());
		final SpringsPersistenceOrmClientsClientProperties.Client client = clients.getFirst();
		final String basicAuthorizationHeader = basicAuthorizationHeader(client.getName(), assertLoginSuccess ? client.getSecret() : "Wrong");
		final String authenticationStatusResponse = authenticateStatus(httpsRestTemplate, basicAuthorizationHeader);
		final boolean success = (authenticationStatusResponse != null) && (authenticationStatusResponse.equals("Authenticated as " + client.getName()));
		if (assertLoginSuccess) {
			Assertions.assertTrue(success);
		} else {
			Assertions.assertFalse(success);
		}
	}

	private void attemptRequestJwt(final RestTemplate httpsRestTemplate, final boolean assertLoginSuccess) throws Exception {
		final List<SpringsPersistenceOrmClientsClientProperties.Client> clients = springsPersistenceOrmClientsClientProperties().getClient();
		Assertions.assertFalse(clients.isEmpty());
		final SpringsPersistenceOrmClientsClientProperties.Client client = clients.getFirst();
		final String basicAuthorizationHeader = basicAuthorizationHeader(client.getName(), assertLoginSuccess ? client.getSecret() : "Wrong");
		final String authenticateJwtResponse = authenticateJwt(httpsRestTemplate, basicAuthorizationHeader);
		if (assertLoginSuccess) {
			Assertions.assertNotNull(authenticateJwtResponse);
			final JWT jwt = JWTParser.parse(authenticateJwtResponse);
			Assertions.assertNotNull(jwt);
			super.prettyJson().logAndSave(jwt.getHeader().toJSONObject());
			if (jwt instanceof SignedJWT) {
				super.prettyJson().logAndSave(jwt.getJWTClaimsSet().toJSONObject());
			}
			final String bearerAuthorizationHeader = bearerAuthorizationHeader(jwt);
			final String authenticationStatusResponse = authenticateStatus(httpsRestTemplate, bearerAuthorizationHeader);
			final boolean success = (authenticationStatusResponse != null) && (authenticationStatusResponse.equals("Authenticated as " + client.getName()));
			Assertions.assertTrue(success);
		} else {
			Assertions.assertNull(authenticateJwtResponse);
		}
	}

	private String authenticateStatus(final RestTemplate httpsRestTemplate, final String authorizationHeader) {
		try {
			final String response = RestTemplateUtil.plainGet(httpsRestTemplate, httpsBaseUrl() + "/api/v1/authenticate/status", authorizationHeader, String.class);
			log.info("Authentication status response: {}", response);
			return response;
		} catch(Exception e) {
			log.warn("Authentication status request failed", e);
			return null;
		}
	}

	private String authenticateJwt(final RestTemplate httpsRestTemplate, final String authorizationHeader) {
		try {
			final String response = RestTemplateUtil.plainPost(httpsRestTemplate, null, httpsBaseUrl() + "/api/v1/authenticate/jwt", authorizationHeader, String.class);
			log.info("Request JWT response: {}", response);
			return response;
		} catch(Exception e) {
			log.warn("Request JWT failed", e);
			return null;
		}
	}

	private static String basicAuthorizationHeader(final String name, final String secret) {
		return "Basic " + Base64Util.STD.encodeToString((name + ":" + secret).getBytes(StandardCharsets.UTF_8));
	}

	private static String bearerAuthorizationHeader(final JWT jwt) {
		return "Bearer " + jwt.serialize();
	}
}
