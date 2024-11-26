package com.github.justincranford.springs.util.http.client.util;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.util.CollectionUtils;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

@NoArgsConstructor(access=AccessLevel.PRIVATE)
@Slf4j
@SuppressWarnings({"unused"})
public final class RestTemplateUtil {
	private static final JsonFactory  JSON_FACTORY                  = new JsonFactory();
	private static final ObjectMapper OBJECT_MAPPER                 = new ObjectMapper();
	private static final List<String> USER_AGENT                    = listOrNull("JustinCranford/1.0");
	private static final List<String> CONTENT_TYPE_APPLICATION_JSON = listOrNull("application/json; charset=utf-8");
	private static final List<String> CONTENT_TYPE_PLAIN_TEXT       = listOrNull("plain/text; charset=utf-8");
	private static final List<String> ACCEPT_APPLICATION_JSON       = listOrNull("application/json");
	private static final List<String> ACCEPT_PLAIN_TEXT             = listOrNull("plain/text");
	private static final List<String> ACCEPT_ALL                    = listOrNull("*/*");
	private static final List<String> ACCEPT_LANGUAGE               = listOrNull("en-US,en;q=0.9");

	public static <RESPONSE> RESPONSE anyGet(final RestTemplate restTemplate, final String url, final String authorization, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHeaders(url, listOrNull(authorization), ACCEPT_ALL, ACCEPT_LANGUAGE)), clazz);
	}

	public static <RESPONSE> RESPONSE plainGet(final RestTemplate restTemplate, final String url, final String authorization, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHeaders(url, listOrNull(authorization), ACCEPT_PLAIN_TEXT, ACCEPT_LANGUAGE)), clazz);
	}
	public static <REQUEST, RESPONSE> RESPONSE plainPost(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final String authorization, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHeaders(url, listOrNull(authorization), ACCEPT_PLAIN_TEXT, ACCEPT_LANGUAGE, CONTENT_TYPE_PLAIN_TEXT)), clazz);
	}

	public static <RESPONSE> RESPONSE jsonGet(final RestTemplate restTemplate, final String url, final String authorization, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHeaders(url, listOrNull(authorization), ACCEPT_APPLICATION_JSON, ACCEPT_LANGUAGE)), clazz);
	}
	public static <REQUEST, RESPONSE> RESPONSE jsonPost(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final String authorization, final Class<RESPONSE> clazz) {
		return http(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHeaders(url, listOrNull(authorization), ACCEPT_APPLICATION_JSON, ACCEPT_LANGUAGE, CONTENT_TYPE_APPLICATION_JSON)), clazz);
	}
	private static <REQUEST, RESPONSE> RESPONSE http(final RestTemplate restTemplate, final String url, final HttpMethod method, final HttpEntity<REQUEST> entity, final Class<RESPONSE> clazz) {
		try {
			log.debug("Method: [{}], URL: [{}], entity: [{}], class: [{}]", method, url, entity, clazz);
			final ResponseEntity<RESPONSE> response = restTemplate.exchange(url, method, entity, clazz);
			final RESPONSE body = response.getBody();
			log.debug("Success\nStatus Code: {}\nResponse Headers: {}\nResponse Body: {}", response.getStatusCode(), response.getHeaders(), body);
			return body;
		} catch (HttpStatusCodeException e) {
        	log.error("Error Response: [" + e.getStatusCode() + "]\nResponse headers:\n" + e.getResponseHeaders() + "\nResponse body: " + e.getResponseBodyAsString());
			throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
		}
	}

	public static <RESPONSE> BlockingQueue<RESPONSE> jsonGetStream(final RestTemplate restTemplate, final String url, final String authorization, final Class<RESPONSE> clazz) {
		return httpStream(restTemplate, url, HttpMethod.GET, new HttpEntity<>(getHeaders(url, listOrNull(authorization), ACCEPT_APPLICATION_JSON, ACCEPT_LANGUAGE)), clazz);
	}
	public static <REQUEST, RESPONSE> BlockingQueue<RESPONSE> jsonPostStream(final RestTemplate restTemplate, final REQUEST postRequest, final String url, final String authorization, final Class<RESPONSE> clazz) {
		return httpStream(restTemplate, url, HttpMethod.POST, new HttpEntity<>(postRequest, postHeaders(url, listOrNull(authorization), ACCEPT_APPLICATION_JSON, ACCEPT_LANGUAGE, CONTENT_TYPE_APPLICATION_JSON)), clazz);
	}

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
					try (JsonParser parser = JSON_FACTORY.createParser(new BufferedReader(new InputStreamReader(clientHttpResponse.getBody(), StandardCharsets.UTF_8)))) {
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
			log.error("HTTP Error Response: [{}]\nResponse body: {}", e.getStatusCode(), e.getResponseBodyAsString());
			throw new RuntimeException("HTTP Error Response: [" + e.getStatusCode() + "]", e);
		} catch (Exception e) {
			log.error("Error processing streaming response", e);
			throw new RuntimeException("Error processing streaming response", e);
		}
	}

	private static HttpHeaders getHeaders(final String url, final List<String> authorization, final List<String> accept, final List<String> acceptLanguage) {
		return postHeaders(url, authorization, accept, acceptLanguage, null);
	}

	private static HttpHeaders postHeaders(final String url, final List<String> authorization, final List<String> accept, final List<String> acceptLanguage, final List<String> contentType) {
		final Map<String,List<String>> multiValueMap = new LinkedHashMap<>();
		multiValueMap.put("User-Agent", USER_AGENT);

		final URL urlObj = url(url);
		multiValueMap.put("Host",   List.of(urlObj.getAuthority()));
		multiValueMap.put("Origin", List.of(urlObj.getProtocol() + "://" + urlObj.getAuthority()));

		putNotNull(multiValueMap, "Authorization",   authorization);
		putNotNull(multiValueMap, "Content-Type",    contentType);
		putNotNull(multiValueMap, "Accept",          accept);
		putNotNull(multiValueMap, "Accept-Language", acceptLanguage);
		return new HttpHeaders(CollectionUtils.toMultiValueMap(multiValueMap));
	}

	private static List<String> listOrNull(final String value) {
		return (value == null) ? null : List.of(value);
	}

	private static void putNotNull(final Map<String,List<String>> map, final String key, final List<String> values) {
		if ((key != null) && (values != null)) {
			map.put(key, values);
		}
	}

	protected static URL url(final String url)  {
		try {
			return new URI(url).toURL();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
	}
}
