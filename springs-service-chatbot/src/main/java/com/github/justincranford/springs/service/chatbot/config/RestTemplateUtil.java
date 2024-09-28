package com.github.justincranford.springs.service.chatbot.config;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import lombok.extern.slf4j.Slf4j;

@SuppressWarnings({"nls"})
@Slf4j
public class RestTemplateUtil {
	private static final List<String> USER_AGENT                    = List.of("JustinCranford/1.0");
	private static final List<String> ACCEPT_LANGUAGE               = List.of("en-US,en;q=0.9");
	private static final List<String> CONTENT_TYPE_APPLCIATION_JSON = List.of("application/json; charset=utf-8");
	private static final List<String> ACCEPT_APPLCIATION_JSON       = List.of("application/json");

	private static final HttpHeaders GET_JSON_HEADERS = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
		"Host",            List.of("localhost:11434"),
		"User-Agent",      USER_AGENT,
		"Accept-Language", ACCEPT_LANGUAGE,
		"Accept",          ACCEPT_APPLCIATION_JSON
	)));

	private static final HttpHeaders POST_JSON_HEADERS = new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
		"Host",            List.of("localhost:11434"),
		"User-Agent",      USER_AGENT,
		"Content-Type", CONTENT_TYPE_APPLCIATION_JSON,
		"Accept",       ACCEPT_APPLCIATION_JSON
	)));

	public static <T> T jsonGet(final RestTemplate restTemplate, final String url, final Class<T> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(GET_JSON_HEADERS), clazz);
	}

	public static <T> T jsonPost(final RestTemplate restTemplate, final String postRequest, final String url, final Class<T> clazz) {
		return http(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, POST_JSON_HEADERS), clazz);
	}

	private static <T> T http(final RestTemplate restTemplate, final String url, final HttpMethod method, final HttpEntity<String> entity, final Class<T> clazz) {
		try {
        	log.error("Method: [{}], URL: [{}], entity: [{}], class: [{}]", method, url, entity, clazz);
			final ResponseEntity<T> response = restTemplate.exchange(url, method, entity, clazz);
            return response.getBody();
        } catch (HttpStatusCodeException e) {
        	log.error("HTTP Error Response: [" + e.getStatusCode() + "]\nResponse body: " + e.getResponseBodyAsString());
            throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
        }
	}
}
