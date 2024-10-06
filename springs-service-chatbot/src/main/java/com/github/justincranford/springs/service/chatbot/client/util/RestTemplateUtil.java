package com.github.justincranford.springs.service.chatbot.client.util;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.extern.slf4j.Slf4j;

@SuppressWarnings({ "nls" })
@Slf4j
public class RestTemplateUtil {
	private static final JsonFactory JSON_FACTORY = new JsonFactory();
	private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
	private static final List<String> USER_AGENT = List.of("JustinCranford/1.0");
	private static final List<String> ACCEPT_LANGUAGE = List.of("en-US,en;q=0.9");
	private static final List<String> CONTENT_TYPE_APPLCIATION_JSON = List.of("application/json; charset=utf-8");
	private static final List<String> ACCEPT_APPLCIATION_JSON = List.of("application/json");

	public static <RESPONSE> RESPONSE jsonGet(final RestTemplate restTemplate, final String url, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHttpHeaders(url)), clazz);
	}
	public static <REQUEST, RESPONSE> RESPONSE jsonPost(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHttpHeaders(url)), clazz);
	}
	private static <REQUEST, RESPONSE> RESPONSE http(final RestTemplate restTemplate, final String url, final HttpMethod method, final HttpEntity<REQUEST> entity, final Class<RESPONSE> clazz) {
		try {
			log.debug("Method: [{}], URL: [{}], entity: [{}], class: [{}]", method, url, entity, clazz);
			final ResponseEntity<RESPONSE> response = restTemplate.exchange(url, method, entity, clazz);
			return response.getBody();
		} catch (HttpStatusCodeException e) {
			log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse body: " + e.getResponseBodyAsString());
			throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
		}
	}

	public static <RESPONSE> BlockingQueue<RESPONSE> jsonGetStream(final RestTemplate restTemplate, final String url, final Class<RESPONSE> clazz) {
		return httpStream(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHttpHeaders(url)), clazz);
	}
	public static <REQUEST, RESPONSE> BlockingQueue<RESPONSE> jsonPostStream(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final Class<RESPONSE> clazz) {
		return httpStream(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHttpHeaders(url)), clazz);
	}

	@SuppressWarnings("resource")
	private static <REQUEST, RESPONSE> BlockingQueue<RESPONSE> httpStream(final RestTemplate restTemplate, final String url, final HttpMethod method, final HttpEntity<REQUEST> entity, final Class<RESPONSE> clazz) {
		try {
			final BlockingQueue<RESPONSE> responseQueue = new LinkedBlockingQueue<>();
			log.debug("Method: [{}], URL: [{}], entity: [{}], class: [{}]", method, url, entity, clazz);
			restTemplate.execute(
				url,
				method,
				clientHttpRequest -> {
					if (entity.getHeaders() != null) {
						clientHttpRequest.getHeaders().putAll(entity.getHeaders());
					}
					if (entity.getBody() != null) {
						clientHttpRequest.getBody().write(OBJECT_MAPPER.writeValueAsBytes(entity.getBody()));
					}
				},
				(clientHttpResponse) -> {
					try (JsonParser parser = JSON_FACTORY.createParser(new BufferedReader(new InputStreamReader(clientHttpResponse.getBody())))) {
					    while (!parser.isClosed()) {
					        if (parser.nextToken() == null) {
					            break;
					        }
					        responseQueue.add(OBJECT_MAPPER.readValue(parser, clazz));
					    }
					}
				    return null;
				}
			);
			return responseQueue;
		} catch (HttpStatusCodeException e) {
			log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse body: " + e.getResponseBodyAsString());
			throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
		} catch (Exception e) {
			log.error("Error processing streaming response", e);
			throw new RuntimeException("Error processing streaming response", e);
		}
	}

	private static HttpHeaders getHttpHeaders(final String url) {
		return new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"Host",				List.of(hostHeaderFromUrl(url)),
			"User-Agent",		USER_AGENT,
			"Accept-Language",	ACCEPT_LANGUAGE,
			"Accept", 			ACCEPT_APPLCIATION_JSON)
		));
	}

	private static HttpHeaders postHttpHeaders(final String url) {
		return new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"Host",				List.of(hostHeaderFromUrl(url)),
			"User-Agent",		USER_AGENT,
			"Content-Type",		CONTENT_TYPE_APPLCIATION_JSON,
			"Accept-Language",	ACCEPT_LANGUAGE,
			"Accept",			ACCEPT_APPLCIATION_JSON)
		));
	}

	private static String hostHeaderFromUrl(final String url) {
		try {
			final URI    uri     = new URI(url);
			final String address = uri.getHost();
			final int    port    = uri.getPort();
			return address + (port == -1 ? "" : ":" + port);
		} catch (URISyntaxException e) {
			throw new RuntimeException(e);
		}
	}
}
