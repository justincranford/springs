package com.github.justincranford.springs.util.http.client.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class SpringsUtilHttpClientConfiguration {
	@Autowired
	private RestTemplateBuilder restTemplateBuilder;

	@Qualifier("httpRestTemplate")
	@Bean
	public RestTemplate httpRestTemplate() {
		return this.restTemplateBuilder.build();
	}
}
