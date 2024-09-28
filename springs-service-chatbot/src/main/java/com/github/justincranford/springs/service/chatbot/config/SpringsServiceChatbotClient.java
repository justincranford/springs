package com.github.justincranford.springs.service.chatbot.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.service.chatbot.properties.SpringsServiceChatbotProperties;

import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@SuppressWarnings({"nls"})
public class SpringsServiceChatbotClient {
	@Autowired
	private SpringsServiceChatbotProperties springsServiceChatbotProperties;

	@Autowired
	private RestTemplate restTemplate;

	private String baseUrl;

	@PostConstruct
	public void postConstruct() {
		this.baseUrl = this.springsServiceChatbotProperties.getProtocol() + "://" + this.springsServiceChatbotProperties.getHost() + ":" + this.springsServiceChatbotProperties.getPort();
		log.info("baseUrl: {}", this.baseUrl);
	}

	public String isAlive() {
		return RestTemplateUtil.jsonGet(this.restTemplate, this.baseUrl + "/", String.class);
	}

	public String tags() {
		return RestTemplateUtil.jsonGet(this.restTemplate, this.baseUrl + "/api/tags", String.class);
	}

	public String ps() {
		return RestTemplateUtil.jsonGet(this.restTemplate, this.baseUrl + "/api/ps", String.class);
	}

	public String chat(final String request) {
		return RestTemplateUtil.jsonPost(this.restTemplate, request, this.baseUrl + "/api/chat", String.class);
	}

//	public String runModel(final String model) {
//		return RestTemplateUtil.jsonGet(this.restTemplate, this.url + "/api/ps", String.class);
//	}
}
