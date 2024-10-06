package com.github.justincranford.springs.service.http.client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
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
	private static final List<String> CONTENT_TYPE_PLAIN_TEXT = List.of("plain/text; charset=utf-8");
	private static final List<String> ACCEPT_APPLCIATION_JSON = List.of("application/json");
	private static final List<String> ACCEPT_PLAIN_TEXT = List.of("plain/text");
	private static final List<String> ACCEPT_ALL = List.of("*/*");

	protected static URL url(final String url)  {
		try {
			return new URI(url).toURL();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	public static <RESPONSE> RESPONSE anyGet(final RestTemplate restTemplate, final String url, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHttpHeaders(url, ACCEPT_ALL)), clazz);
	}

	public static <RESPONSE> RESPONSE plainGet(final RestTemplate restTemplate, final String url, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHttpHeaders(url, ACCEPT_PLAIN_TEXT)), clazz);
	}
	public static <REQUEST, RESPONSE> RESPONSE plainPost(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHttpHeaders(url, CONTENT_TYPE_PLAIN_TEXT, ACCEPT_PLAIN_TEXT)), clazz);
	}

	public static <RESPONSE> RESPONSE jsonGet(final RestTemplate restTemplate, final String url, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHttpHeaders(url, ACCEPT_APPLCIATION_JSON)), clazz);
	}
	public static <REQUEST, RESPONSE> RESPONSE jsonPost(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHttpHeaders(url, CONTENT_TYPE_APPLCIATION_JSON, ACCEPT_APPLCIATION_JSON)), clazz);
	}
	private static <REQUEST, RESPONSE> RESPONSE http(final RestTemplate restTemplate, final String url, final HttpMethod method, final HttpEntity<REQUEST> entity, final Class<RESPONSE> clazz) {
		try {
			log.debug("Method: [{}], URL: [{}], entity: [{}], class: [{}]", method, url, entity, clazz);
			final ResponseEntity<RESPONSE> response = restTemplate.exchange(url, method, entity, clazz);
			final RESPONSE body = response.getBody();
			log.debug("Status Code: {}\nResponse Headers: {}\nResponse Body: {}\nResponse Body: {}", response.getStatusCode(), response.getHeaders(), body);
			return body;
		} catch (HttpStatusCodeException e) {
        	log.error("Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
			throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
		}
	}

	public static <RESPONSE> BlockingQueue<RESPONSE> jsonGetStream(final RestTemplate restTemplate, final String url, final Class<RESPONSE> clazz) {
		return httpStream(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHttpHeaders(url, ACCEPT_APPLCIATION_JSON)), clazz);
	}
	public static <REQUEST, RESPONSE> BlockingQueue<RESPONSE> jsonPostStream(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final Class<RESPONSE> clazz) {
		return httpStream(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHttpHeaders(url, CONTENT_TYPE_APPLCIATION_JSON, ACCEPT_APPLCIATION_JSON)), clazz);
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

	private static HttpHeaders getHttpHeaders(final String urlString, final List<String> accept) {
		final URL url = url(urlString);
		return new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"User-Agent",		USER_AGENT,
			"Host",				List.of(url.getAuthority()),
			"Origin",			List.of(url.getProtocol() + "://" + url.getAuthority()),
			"Accept", 			accept,
			"Accept-Language",	ACCEPT_LANGUAGE
		)));
	}

	private static HttpHeaders postHttpHeaders(final String urlString, final List<String> contentType, final List<String> accept) {
		final URL url = url(urlString);
		return new HttpHeaders(CollectionUtils.toMultiValueMap(Map.of(
			"User-Agent",		USER_AGENT,
			"Host",				List.of(url.getAuthority()),
			"Origin",			List.of(url.getProtocol() + "://" + url.getAuthority()),
			"Content-Type",		contentType,
			"Accept",			accept,
			"Accept-Language",	ACCEPT_LANGUAGE
		)));
	}
}
