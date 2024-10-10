package com.github.justincranford.springs.service.webauthn.tls;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.service.http.client.RestTemplateUtil;
import com.github.justincranford.springs.service.webauthn.AbstractIT;
import com.github.justincranford.springs.service.webauthn.actions.data.ActionsResponse;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings("nls")
public class WebauthnIT extends AbstractIT {
	@Test
	void testHome() {
		final String response = RestTemplateUtil.plainGet(stlsRestTemplate(), httpsBaseUrl() + "/index.html", String.class);
		assertThat(response).contains("WebAuthn");
	}

	@Test
	void testActionsApi() {
		final ActionsResponse response = RestTemplateUtil.anyGet(stlsRestTemplate(), httpsBaseUrl() + "/api/v1", ActionsResponse.class);
		log.info("response: {}", response);
		assertThat(response).isNotNull();
	}
}
