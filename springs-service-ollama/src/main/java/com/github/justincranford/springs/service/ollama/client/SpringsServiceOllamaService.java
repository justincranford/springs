package com.github.justincranford.springs.service.ollama.client;

import java.util.List;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.ai.chat.messages.Message;
import org.springframework.ai.chat.model.ChatResponse;
import org.springframework.ai.chat.prompt.ChatOptions;
import org.springframework.ai.chat.prompt.Prompt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"nls"})
public class SpringsServiceOllamaService {
	@Autowired
	private final ChatClient chatClient;
	@Autowired
	private final ObjectMapper objectMapper;

	public ChatResponse prompt(final List<Message> messages, final ChatOptions chatOptions) {
		try {
			final Prompt request = new Prompt(messages, chatOptions);
	        log.info("Prompt Request:\n{}", request);
			final ChatResponse response = this.chatClient
				.prompt(request)
				.call()
				.chatResponse();
	        log.info("Prompt Response:\n{}", response);
	        return response;
		} catch(Exception e) {
	        log.info("Prompt exception:", e);
	        throw new RuntimeException(e);
		}
	}
}
