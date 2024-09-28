package com.github.justincranford.springs.service.chatbot.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.chatbot.properties.SpringsServiceChatbotProperties;

@Configuration
@EnableConfigurationProperties
@ComponentScan(
	basePackageClasses = {SpringsServiceChatbotProperties.class}
)
@Import({
	SpringsServiceChatbotHttpClient.class
})
public class SpringsServiceChatbotConfiguration {
	// do nothing
}
