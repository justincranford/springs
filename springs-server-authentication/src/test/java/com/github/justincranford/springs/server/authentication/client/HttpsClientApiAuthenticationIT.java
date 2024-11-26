package com.github.justincranford.springs.server.authentication.client;

import com.github.justincranford.springs.persistenceorm.clients.properties.SpringsPersistenceOrmClientsClientProperties;
import com.github.justincranford.springs.server.authentication.AbstractIT;
import com.github.justincranford.springs.util.basic.Base64Util;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
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
			void sTls() throws Exception {
				attemptLoginClientName(stlsRestTemplate(), true);
			}
			@RepeatedTest(REPEATS)
			void mTls() throws Exception {
				attemptLoginClientName(mtlsRestTemplate(), true);
			}
		}

		@Nested
		public class Failure {
			@RepeatedTest(REPEATS)
			void sTls() throws Exception {
				attemptLoginClientName(stlsRestTemplate(), false);
			}
			@RepeatedTest(REPEATS)
			void mTls() throws Exception {
				attemptLoginClientName(mtlsRestTemplate(), false);
			}
		}
	}

	private void attemptUnauthenticatedHttpGet(final RestTemplate httpsRestTemplate) {
		final String response = RestTemplateUtil.plainGet(httpsRestTemplate, httpsBaseUrl() + "/v1/api/authenticate/status", null, String.class);
		assertThat(response).contains("Authenticated as anonymous");
	}

	private void attemptLoginClientName(final RestTemplate httpsRestTemplate, final boolean assertLoginSuccess) throws Exception {
		final List<SpringsPersistenceOrmClientsClientProperties.Client> clients = springsPersistenceOrmClientsClientProperties().getClient();
        Assertions.assertFalse(clients.isEmpty());
		final SpringsPersistenceOrmClientsClientProperties.Client client = clients.getFirst();
		final boolean success = attemptLogin(httpsRestTemplate, client.getName(), assertLoginSuccess ? client.getSecret() : "Wrong");
		if (assertLoginSuccess) {
			Assertions.assertTrue(success);
		} else {
			Assertions.assertFalse(success);
		}
	}

	private boolean attemptLogin(final RestTemplate httpsRestTemplate, final String name, final String secret) {
		final String authorizationHeader = "Basic " + Base64Util.STD.encodeToString((name+":"+secret).getBytes(StandardCharsets.UTF_8));
		try {
			final String response = RestTemplateUtil.plainGet(httpsRestTemplate, httpsBaseUrl() + "/v1/api/authenticate/status", authorizationHeader, String.class);
			log.info("Authentication status response: {}", response);
			return response.equals("Authenticated as " + name);
		} catch(Exception e) {
			return false;
		}
	}
}
