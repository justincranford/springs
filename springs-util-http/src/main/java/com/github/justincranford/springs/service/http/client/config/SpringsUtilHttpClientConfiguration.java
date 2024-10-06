package com.github.justincranford.springs.service.http.client.config;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
@SuppressWarnings({"static-method"})
public class SpringsUtilHttpClientConfiguration {
	@Qualifier("httpRestTemplate")
	@Bean
	public RestTemplate httpRestTemplate(final RestTemplateBuilder restTemplateBuilder) {
		return restTemplateBuilder.build();
	}
}
