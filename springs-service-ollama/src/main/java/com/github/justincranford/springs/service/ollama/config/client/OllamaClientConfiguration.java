package com.github.justincranford.springs.service.ollama.config.client;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.ollama.OllamaChatModel;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.ollama.client.SpringsServiceOllama;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Import({SpringsServiceOllama.class})
@SuppressWarnings({"static-method"})
@RequiredArgsConstructor
@Slf4j
public class OllamaClientConfiguration {
	@Bean
	public ChatClient chatClient(final OllamaChatModel ollamaChatModel) {
		return ChatClient.builder(ollamaChatModel).build();
	}
}
