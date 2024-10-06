package com.github.justincranford.springs.util.certs.tls;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpStatusCodeException;

import com.github.justincranford.springs.util.certs.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings("nls")
public class TomcatTlsInitializerIT extends AbstractIT {
	@Test
	void testTlsMutualAuthentication() {
		final HttpHeaders headers = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"Host",   List.of(serverAddress() + ":" + localServerPort()),
			"Accept", List.of("*/*")
		)));
		final String url = "https://" + serverAddress() + ":" + localServerPort();
		log.info("url: {}", url);
		try {
			final ResponseEntity<String> x = tlsMutualAuthenticationRestTemplate().exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
			log.info("HTTPS Status Code: {}\nResponse Headers: {}\nResponse Body: {}", x.getStatusCode(), x.getHeaders(), x.getBody());
			assertThat(x.getBody()).isEqualTo(HTTP_ROOT_RESPONSE_BODY);
        } catch (HttpStatusCodeException e) {
        	log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
            throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
		}
	}

	@Test
	void testTlsServerAuthentication() {
		final HttpHeaders headers = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"Host",   List.of(serverAddress() + ":" + localServerPort()),
			"Accept", List.of("*/*")
		)));
		final String url = "https://" + serverAddress() + ":" + localServerPort();
		log.info("url: {}", url);
		try {
			final ResponseEntity<String> x = tlsServerAuthenticationRestTemplate().exchange(url, HttpMethod.GET, new HttpEntity<>(headers), String.class);
			log.info("HTTPS Status Code: {}\nResponse Headers: {}\nResponse Body: {}", x.getStatusCode(), x.getHeaders(), x.getBody());
			assertThat(x.getBody()).isEqualTo(HTTP_ROOT_RESPONSE_BODY);
        } catch (HttpStatusCodeException e) {
        	log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
            throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
		}
	}
}
