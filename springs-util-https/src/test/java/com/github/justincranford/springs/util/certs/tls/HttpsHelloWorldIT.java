package com.github.justincranford.springs.util.certs.tls;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assumptions.assumeThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpStatusCodeException;

import com.github.justincranford.springs.service.http.server.HelloWorldController;
import com.github.justincranford.springs.util.certs.AbstractIT;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
@SuppressWarnings("nls")
public class HttpsHelloWorldIT extends AbstractIT {
	private String httpUrl;
	private String httpsUrl;

	@BeforeEach
	public void beforeEach() {
		this.httpUrl  = "http://"  + serverAddress() + ":" + localServerPort() + "/helloworld";
		this.httpsUrl = "https://" + serverAddress() + ":" + localServerPort() + "/helloworld";
		log.info("urls, http: {}, https: {}", this.httpUrl, this.httpsUrl);
	}

	@Nested
	public class ConditionalBeans {
		@Test
		void testConditionalBeans() {
			assertThat(httpRestTemplate()).isNotNull();
			if (sslAutoConfigEnabled()) {
				assertThat(mtlsRestTemplate()).isNotNull();
				assertThat(mtlsRestTemplate()).isNotNull();
			} else {
				assertThat(mtlsRestTemplate()).isNull();
				assertThat(mtlsRestTemplate()).isNull();
			}
		}
	}

	@Nested
	public class HttpClient {
		@Test
		void testHttpClientFailIfHttpsServer() {
			assumeThat(sslAutoConfigEnabled()).isTrue();
			final HttpHeaders headers = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
				"Host",   List.of(serverAddress() + ":" + localServerPort()),
				"Accept", List.of("*/*")
			)));
			assertThatThrownBy(() -> {
				try {
					final ResponseEntity<String> x = httpRestTemplate().exchange(HttpsHelloWorldIT.this.httpUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class);
					log.info("HTTPS Status Code: {}\nResponse Headers: {}\nResponse Body: {}", x.getStatusCode(), x.getHeaders(), x.getBody());
		        } catch (HttpStatusCodeException e) {
		        	log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
		            throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
				}
			});
		}

		@Test
		void testHttpsClientPassIfHttpsServer() {
			assumeThat(sslAutoConfigEnabled()).isFalse();
			final HttpHeaders headers = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
				"Host",   List.of(serverAddress() + ":" + localServerPort()),
				"Accept", List.of("*/*")
			)));
			try {
				final ResponseEntity<String> x = httpRestTemplate().exchange(HttpsHelloWorldIT.this.httpUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class);
				log.info("HTTPS Status Code: {}\nResponse Headers: {}\nResponse Body: {}", x.getStatusCode(), x.getHeaders(), x.getBody());
				assertThat(x.getBody()).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	        } catch (HttpStatusCodeException e) {
	        	log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
	            throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
			}
		}
	}

	@Nested
	public class HttpsClientServerTls {
		@Test
		void testHttpTlsServerAuthentication() {
			assumeThat(sslAutoConfigEnabled()).isTrue();
			final HttpHeaders headers = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
				"Host",   List.of(serverAddress() + ":" + localServerPort()),
				"Accept", List.of("*/*")
			)));
			try {
				final ResponseEntity<String> x = stlsRestTemplate().exchange(HttpsHelloWorldIT.this.httpsUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class);
				log.info("HTTPS Status Code: {}\nResponse Headers: {}\nResponse Body: {}", x.getStatusCode(), x.getHeaders(), x.getBody());
				assertThat(x.getBody()).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	        } catch (HttpStatusCodeException e) {
	        	log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
	            throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
			}
		}
	}

	@Nested
	public class HttpsClientMutualTls {
		@Test
		void testHttpTlsMutualAuthentication() {
			assumeThat(sslAutoConfigEnabled()).isTrue();
			final HttpHeaders headers = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
				"Host",   List.of(serverAddress() + ":" + localServerPort()),
				"Accept", List.of("*/*")
			)));
			try {
				final ResponseEntity<String> x = mtlsRestTemplate().exchange(HttpsHelloWorldIT.this.httpsUrl, HttpMethod.GET, new HttpEntity<>(headers), String.class);
				log.info("HTTPS Status Code: {}\nResponse Headers: {}\nResponse Body: {}", x.getStatusCode(), x.getHeaders(), x.getBody());
				assertThat(x.getBody()).isEqualTo(HelloWorldController.Constants.RESPONSE_BODY);
	        } catch (HttpStatusCodeException e) {
	        	log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
	            throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
			}
		}
	}
}
