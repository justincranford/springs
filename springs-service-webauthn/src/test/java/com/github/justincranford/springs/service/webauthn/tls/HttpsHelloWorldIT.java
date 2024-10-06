package com.github.justincranford.springs.service.webauthn.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import com.github.justincranford.springs.service.http.client.RestTemplateUtil;
import com.github.justincranford.springs.service.http.server.HelloWorldController;
import com.github.justincranford.springs.service.webauthn.AbstractIT;

@SuppressWarnings({"nls"})
public class HttpsHelloWorldIT extends AbstractIT {
	@Test
	void testHttpSuccess() {
		assertThatThrownBy(
			() -> RestTemplateUtil.plainGet(httpRestTemplate(), httpBaseUrl() + HelloWorldController.Constants.PATH, String.class)
		)
		.isInstanceOf(RuntimeException.class)
		.hasMessage("HTTP Error Response: [400 BAD_REQUEST]")
		.cause()
		.isInstanceOf(HttpClientErrorException.class)
		.hasMessage("400 : \"Bad Request<EOL><EOL>This combination of host and port requires TLS.<EOL><EOL>\"");
	}

	@Test
	void testHttpsSuccessServerTls() {
		final String response = RestTemplateUtil.plainGet(stlsRestTemplate(), httpsBaseUrl() + HelloWorldController.Constants.PATH, String.class);
		assertThat(response).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	}

	@Test
	void testHttpsSuccessMutualTls() {
		final String response = RestTemplateUtil.plainGet(mtlsRestTemplate(), httpsBaseUrl() + HelloWorldController.Constants.PATH, String.class);
		assertThat(response).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	}
}
