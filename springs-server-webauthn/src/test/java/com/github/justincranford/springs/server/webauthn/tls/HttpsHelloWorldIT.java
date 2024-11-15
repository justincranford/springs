package com.github.justincranford.springs.server.webauthn.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.apache.hc.core5.http.NoHttpResponseException;
import org.assertj.core.api.AbstractThrowableAssert;
import org.assertj.core.api.Fail;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.HttpClientErrorException;

import com.github.justincranford.springs.server.webauthn.AbstractIT;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import com.github.justincranford.springs.util.http.server.helloworld.HelloWorldController;

public class HttpsHelloWorldIT extends AbstractIT {
	@Test
	void testHttpFailure() {
		final AbstractThrowableAssert<?, ? extends Throwable> assertThatThrownBy = assertThatThrownBy(
			() -> RestTemplateUtil.plainGet(httpRestTemplate(), httpBaseUrl() + HelloWorldController.Constants.PATH, String.class)
		);
		final String webServerClassName = webServerApplicationContext().getWebServer().getClass().getName();
		if (webServerClassName.contains("Tomcat")) {
			assertThatThrownBy
				.isInstanceOf(RuntimeException.class)
				.hasMessage("HTTP Error Response: [400 BAD_REQUEST]")
				.cause()
				.isInstanceOf(HttpClientErrorException.class)
				.hasMessage("400 : \"Bad Request<EOL><EOL>This combination of host and port requires TLS.<EOL><EOL>\"");
		} else if (webServerClassName.contains("Jetty")) {
			assertThatThrownBy
				.isInstanceOf(RuntimeException.class)
				.hasMessage("I/O error on GET request for \"http://localhost:8443/helloworld\": localhost:8443 failed to respond")
				.cause()
				.isInstanceOf(NoHttpResponseException.class)
				.hasMessage("localhost:8443 failed to respond");
		} else {
			Fail.fail("Unsupported webserver class: {}", webServerClassName);
		}
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
