package com.github.justincranford.springs.service.http.client;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import javax.net.ssl.SSLException;

import org.junit.jupiter.api.Test;
import org.springframework.web.client.ResourceAccessException;

import com.github.justincranford.springs.service.http.AbstractIT;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import com.github.justincranford.springs.util.http.server.helloworld.HelloWorldController;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class HttpHelloWorldIT extends AbstractIT {
	private static final String AUTHORIZE = null;

	@Test
	void testHttpSuccess() {
		final String response = RestTemplateUtil.plainGet(httpRestTemplate(), httpBaseUrl() + HelloWorldController.Constants.PATH, AUTHORIZE, String.class);
		assertThat(response).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	}

	@Test
	void testHttpsFail() {
		assertThatThrownBy(
			() -> RestTemplateUtil.plainGet(httpRestTemplate(), httpsBaseUrl() + HelloWorldController.Constants.PATH, AUTHORIZE, String.class)
		)
		.isInstanceOf(ResourceAccessException.class)
		.hasMessage("I/O error on GET request for \"" + httpsBaseUrl() + HelloWorldController.Constants.PATH + "\": Unrecognized SSL message, plaintext connection?")
		.cause()
		.isInstanceOf(SSLException.class)
		.hasMessage("Unrecognized SSL message, plaintext connection?"); // Unsupported or unrecognized SSL message
	}
}
