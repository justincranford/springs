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
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationServerStart;
import com.github.justincranford.springs.service.webauthn.register.data.RegistrationClientFinish;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings({"nls"})
public class WebauthnIT extends AbstractIT {
    @Value("classpath:non-resident-registration-request.json")
    private Resource nonResidentRegistrationServerStartJson;

    @Value("classpath:non-resident-registration-response.json")
    private Resource nonResidentRegistrationClientFinishJson;

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
		final RegistrationServerStart registrationClientServerStart = objectMapper().readValue(this.nonResidentRegistrationServerStartJson.getContentAsString(StandardCharsets.UTF_8), RegistrationServerStart.class);
		assertThat(registrationClientServerStart).isNotNull();
		final String registrationRequestJson  = objectMapper().writeValueAsString(registrationClientServerStart);
		assertThat(registrationRequestJson).isNotNull();
	}

	@Test
	void parseRegistrationResponse() throws IOException {
		final RegistrationClientFinish registrationClientFinish = objectMapper().readValue(this.nonResidentRegistrationClientFinishJson.getContentAsString(StandardCharsets.UTF_8), RegistrationClientFinish.class);
		assertThat(registrationClientFinish).isNotNull();
		final String registrationResponseJson  = objectMapper().writeValueAsString(registrationClientFinish);
		assertThat(registrationResponseJson).isNotNull();
	}
}
