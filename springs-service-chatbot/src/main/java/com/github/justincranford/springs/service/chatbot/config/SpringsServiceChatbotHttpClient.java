package com.github.justincranford.springs.service.chatbot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

@Configuration
@SuppressWarnings({"static-method"})
public class SpringsServiceChatbotHttpClient {
	@Bean
	public SpringsServiceChatbotClient springsServiceChatbotClient() {
		return new SpringsServiceChatbotClient();
	}

	@Bean
	public RestTemplate restTemplate() {
		final RestTemplate restTemplate = new RestTemplate();
		restTemplate.setErrorHandler(new DefaultResponseErrorHandler());
		return restTemplate;
	}
}
