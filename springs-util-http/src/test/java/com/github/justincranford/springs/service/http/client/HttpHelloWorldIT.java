package com.github.justincranford.springs.service.http.client;

import com.github.justincranford.springs.service.http.AbstractIT;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import com.github.justincranford.springs.util.http.server.helloworld.HelloWorldController;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.ResourceAccessException;

import javax.net.ssl.SSLException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Slf4j
public class HttpHelloWorldIT extends AbstractIT {
	private static final String NO_AUTHORIZATION = null;

	@Test
	void testHttpSuccess() {
		final String response = RestTemplateUtil.plainGet(httpRestTemplate(), httpBaseUrl() + HelloWorldController.Constants.PATH, NO_AUTHORIZATION, String.class);
		assertThat(response).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	}

	@Test
	void testHttpsFail() {
		assertThatThrownBy(
			() -> RestTemplateUtil.plainGet(httpRestTemplate(), httpsBaseUrl() + HelloWorldController.Constants.PATH, NO_AUTHORIZATION, String.class)
		)
		.isInstanceOf(ResourceAccessException.class)
		.hasMessage("I/O error on GET request for \"" + httpsBaseUrl() + HelloWorldController.Constants.PATH + "\": Unrecognized SSL message, plaintext connection?")
		.cause()
		.isInstanceOf(SSLException.class)
		.hasMessage("Unrecognized SSL message, plaintext connection?"); // Unsupported or unrecognized SSL message
	}
}
