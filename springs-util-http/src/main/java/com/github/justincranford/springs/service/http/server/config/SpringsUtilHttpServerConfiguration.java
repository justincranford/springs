package com.github.justincranford.springs.service.http.server.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.service.http.server.HelloWorldController;

@Configuration
@Import({HelloWorldController.class})
public class SpringsUtilHttpServerConfiguration {
	// do nothing
}
