package com.github.justincranford.springs.util.http.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import com.github.justincranford.springs.util.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.http.server.config.SpringsUtilHttpServerConfiguration;

import lombok.extern.slf4j.Slf4j;

@Configuration
@Import(value={
	SpringsUtilHttpClientConfiguration.class,
	SpringsUtilHttpServerConfiguration.class
})
@Slf4j
public class SpringsUtilHttpConfiguration {
	// do nothing
}
