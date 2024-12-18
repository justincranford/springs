package com.github.justincranford.springs.server.webauthn.tls;

import com.github.justincranford.springs.server.webauthn.AbstractIT;
import com.github.justincranford.springs.util.http.client.util.RestTemplateUtil;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;

import static org.assertj.core.api.Assertions.assertThat;

@Configuration
@Slf4j
@SuppressWarnings({"unused"})
public class WebauthnIT extends AbstractIT {
    private static final String NO_AUTHORIZATION = null;

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
		final String response = RestTemplateUtil.plainGet(stlsRestTemplate(), httpsBaseUrl() + "/index.html", NO_AUTHORIZATION, String.class);
		assertThat(response).contains("WebAuthn");
	}
}
