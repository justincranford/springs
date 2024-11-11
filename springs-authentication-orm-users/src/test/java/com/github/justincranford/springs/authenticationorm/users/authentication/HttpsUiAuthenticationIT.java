package com.github.justincranford.springs.authenticationorm.users.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.apache.hc.core5.http.NoHttpResponseException;
import org.assertj.core.api.AbstractThrowableAssert;
import org.junit.jupiter.api.Test;

import com.github.justincranford.springs.authenticationorm.users.AbstractIT;
import com.github.justincranford.springs.service.http.client.RestTemplateUtil;

@SuppressWarnings({"nls"})
public class HttpsUiAuthenticationIT extends AbstractIT {
	@Test
	void testHttpsLoginSuccess_personPassword_serverTls() {
		final String response = RestTemplateUtil.plainGet(stlsRestTemplate(), httpsBaseUrl() + "/login", String.class);
		assertThat(response).contains("action=\"/login\"");
	}

	@Test
	void testHttpsLoginSuccess_personPassword_mutualTls() {
		final String response = RestTemplateUtil.plainGet(mtlsRestTemplate(), httpsBaseUrl() + "/login", String.class);
		assertThat(response).contains("action=\"/login\"");
	}

	@Test
	void testHttpsLoginFailure() {
		final AbstractThrowableAssert<?, ? extends Throwable> assertThatThrownBy = assertThatThrownBy(
			() -> RestTemplateUtil.plainGet(httpRestTemplate(), httpBaseUrl() + "/login", String.class)
		);
		assertThatThrownBy
			.isInstanceOf(RuntimeException.class)
			.hasMessage("I/O error on GET request for \"http://localhost:8443/login\": localhost:8443 failed to respond")
			.cause()
			.isInstanceOf(NoHttpResponseException.class)
			.hasMessage("localhost:8443 failed to respond");
	}
}
