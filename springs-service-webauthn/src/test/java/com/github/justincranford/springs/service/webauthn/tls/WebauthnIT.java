package com.github.justincranford.springs.service.webauthn.tls;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import com.github.justincranford.springs.service.http.client.RestTemplateUtil;
import com.github.justincranford.springs.service.webauthn.AbstractIT;
import com.github.justincranford.springs.service.webauthn.actions.data.ActionsResponse;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationRequest;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationResponse;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings({"nls"})
public class WebauthnIT extends AbstractIT {
    @Value("classpath:non-resident-registration-request.json")
    private Resource nonResidentRegistrationRequestJson;

    @Value("classpath:non-resident-registration-response.json")
    private Resource nonResidentRegistrationResponseJson;

    @Value("classpath:non-resident-authentication-request.json")
    private Resource nonResidentAuthenticationRequestJson;

    @Value("classpath:non-resident-authentication-response.json")
    private Resource nonResidentAuthenticationResponseJson;

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

	@Test
	void parseRegistrationRequest() throws IOException {
		final RegistrationRequest  registrationRequest  = objectMapper().readValue(this.nonResidentRegistrationRequestJson.getContentAsString(StandardCharsets.UTF_8), RegistrationRequest.class);
		assertThat(registrationRequest).isNotNull();
		final String registrationRequestJson  = objectMapper().writeValueAsString(registrationRequest);
		assertThat(registrationRequestJson).isNotNull();
	}

	@Test
	void parseRegistrationResponse() throws IOException {
		final RegistrationResponse registrationResponse = objectMapper().readValue(this.nonResidentRegistrationResponseJson.getContentAsString(StandardCharsets.UTF_8), RegistrationResponse.class);
		assertThat(registrationResponse).isNotNull();
		final String registrationResponseJson  = objectMapper().writeValueAsString(registrationResponse);
		assertThat(registrationResponseJson).isNotNull();
	}
}
