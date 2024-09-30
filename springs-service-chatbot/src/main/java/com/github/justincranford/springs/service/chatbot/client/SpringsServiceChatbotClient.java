package com.github.justincranford.springs.service.chatbot.client;

import java.util.Objects;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.chatbot.client.util.RestTemplateUtil;
import com.github.justincranford.springs.service.chatbot.model.Chat;
import com.github.justincranford.springs.service.chatbot.model.Generate;
import com.github.justincranford.springs.service.chatbot.model.Ps;
import com.github.justincranford.springs.service.chatbot.model.Pull;
import com.github.justincranford.springs.service.chatbot.model.Tags;
import com.github.justincranford.springs.service.chatbot.properties.SpringsServiceChatbotProperties;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"nls"})
public class SpringsServiceChatbotClient {
	@Autowired
	private final ObjectMapper objectMapper;

	@Autowired
	private final SpringsServiceChatbotProperties springsServiceChatbotProperties;

	@Autowired
	private final RestTemplate restTemplate;

	private String baseUrl;

	@PostConstruct
	public void postConstruct() {
		this.baseUrl = this.springsServiceChatbotProperties.getProtocol() + "://" + this.springsServiceChatbotProperties.getHost() + ":" + this.springsServiceChatbotProperties.getPort();
		log.info("baseUrl: {}", this.baseUrl);
	}

	public boolean alive() {
		try {
			final String response = RestTemplateUtil.jsonGet(this.restTemplate, this.baseUrl, String.class);
	        log.info("isAlive:\n{}", response);
			return Objects.equals(response, "Ollama is running");
		} catch(Exception e) {
	        log.info("isAlive exception:", e);
	        throw new RuntimeException(e);
		}
	}

	public Tags.Response tags() {
		try {
			final Tags.Response response = RestTemplateUtil.jsonGet(this.restTemplate, this.baseUrl + Tags.URL, Tags.Response.class);
	        log.info("tags response:\n{}", response);
			return response;
		} catch(Exception e) {
	        log.info("tags exception:", e);
	        throw new RuntimeException(e);
		}
	}

	public Ps.Response ps() {
		try {
			final Ps.Response response = RestTemplateUtil.jsonGet(this.restTemplate, this.baseUrl + Ps.URL, Ps.Response.class);
	        log.info("ps response:\n{}", this.objectMapper.writeValueAsString(response));
			return response;
		} catch(Exception e) {
	        log.info("ps exception:", e);
	        throw new RuntimeException(e);
		}
	}

	public Pull.Response pull(final Pull.Request request) {
		try {
	        log.info("models request:\n{}", this.objectMapper.writeValueAsString(request));
			final Pull.Response response = RestTemplateUtil.jsonPost(this.restTemplate, request, this.baseUrl + Pull.URL, Pull.Response.class);
	        log.info("models response:\n{}", this.objectMapper.writeValueAsString(response));
			return response;
		} catch(Exception e) {
	        log.info("models exception:", e);
	        throw new RuntimeException(e);
		}
	}

	public Generate.Response generate(final Generate.Request request) {
		try {
	        log.info("generate request:\n{}", this.objectMapper.writeValueAsString(request));
			final Generate.Response response = RestTemplateUtil.jsonPost(this.restTemplate, request, this.baseUrl + Generate.URL, Generate.Response.class);
	        log.info("generate response:\n{}", this.objectMapper.writeValueAsString(response));
			return response;
		} catch(Exception e) {
	        log.info("generate exception:", e);
	        throw new RuntimeException(e);
		}
	}

	public Chat.Response chat(final Chat.Request request) {
		try {
	        log.info("chat request:\n{}", this.objectMapper.writeValueAsString(request));
			final Chat.Response response = RestTemplateUtil.jsonPost(this.restTemplate, request, this.baseUrl + Chat.URL, Chat.Response.class);
	        log.info("chat: {}\n", this.objectMapper.writeValueAsString(response));
			return response;
		} catch(Exception e) {
	        log.info("chat exception:", e);
	        throw new RuntimeException(e);
		}
	}
}
