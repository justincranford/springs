package com.github.justincranford.springs.service.ollama.config.client;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

import com.github.justincranford.springs.service.ollama.client.SpringsServiceOllamaService;

import lombok.extern.slf4j.Slf4j;

@Configuration
@ComponentScan(basePackageClasses = { SpringsServiceOllamaService.class })
@SuppressWarnings({"static-method"})
@Slf4j
public class SpringsServiceOllamaServiceConfiguration {
	@Bean
	public ChatClient chatClient(final ChatClient.Builder chatClientBuilder) {
		return chatClientBuilder.build();
	}
}
