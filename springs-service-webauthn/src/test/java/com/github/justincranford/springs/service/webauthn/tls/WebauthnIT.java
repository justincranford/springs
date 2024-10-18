package com.github.justincranford.springs.service.webauthn.tls;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import com.github.justincranford.springs.service.http.client.RestTemplateUtil;
import com.github.justincranford.springs.service.webauthn.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings({"nls"})
public class WebauthnIT extends AbstractIT {
    @Value("classpath:non-resident-registration-start-client.json")
    private Resource nonResidentRegistrationStartClientJson;

    @Value("classpath:non-resident-registration-start-server.json")
    private Resource nonResidentRegistrationStartServerJson;

    @Value("classpath:non-resident-registration-finish-client.json")
    private Resource nonResidentRegistrationFinishClientJson;

    @Value("classpath:non-resident-registration-finish-server.json")
    private Resource nonResidentRegistrationFinishServerJson;

    @Test
	void testHome() {
		final String response = RestTemplateUtil.plainGet(stlsRestTemplate(), httpsBaseUrl() + "/index.html", String.class);
		assertThat(response).contains("WebAuthn");
	}

//	@Test
//	void parseRegistrationRequest() throws IOException {
//		final RegistrationStartServer registrationClientServerStart = objectMapper().readValue(this.nonResidentRegistrationStartServerJson.getContentAsString(StandardCharsets.UTF_8), RegistrationStartServer.class);
//		assertThat(registrationClientServerStart).isNotNull();
//		final String registrationRequestJson  = objectMapper().writeValueAsString(registrationClientServerStart);
//		assertThat(registrationRequestJson).isNotNull();
//	}
//
//	@Test
//	void parseRegistrationResponse() throws IOException {
//		final RegistrationFinishClient registrationFinishClient = objectMapper().readValue(this.nonResidentRegistrationFinishClientJson.getContentAsString(StandardCharsets.UTF_8), RegistrationFinishClient.class);
//		assertThat(registrationFinishClient).isNotNull();
//		final String registrationResponseJson  = objectMapper().writeValueAsString(registrationFinishClient);
//		assertThat(registrationResponseJson).isNotNull();
//	}
}
