package com.github.justincranford.springs.service.http.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.net.ssl.SSLException;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.ResourceAccessException;

import com.github.justincranford.springs.service.http.AbstractIT;
import com.github.justincranford.springs.service.http.server.HelloWorldController;

@SuppressWarnings({"nls"})
public class HttpHelloWorldIT extends AbstractIT {
	@Test
	void testHttpSuccess() {
		final String response = RestTemplateUtil.plainGet(httpRestTemplate(), httpBaseUrl() + HelloWorldController.Constants.PATH, String.class);
		assertThat(response).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	}

	@Test
	void testHttpsFail() {
		assertThatThrownBy(
			() -> RestTemplateUtil.plainGet(httpRestTemplate(), httpsBaseUrl() + HelloWorldController.Constants.PATH, String.class)
		)
		.isInstanceOf(ResourceAccessException.class)
		.hasMessage("I/O error on GET request for \"" + httpsBaseUrl() + HelloWorldController.Constants.PATH + "\": Unsupported or unrecognized SSL message")
		.cause()
		.isInstanceOf(SSLException.class)
		.hasMessage("Unsupported or unrecognized SSL message");
	}
}
