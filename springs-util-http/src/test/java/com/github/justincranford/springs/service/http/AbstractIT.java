package com.github.justincranford.springs.service.http;

import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.service.http.config.SpringsUtilHttpConfiguration;

import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
	webEnvironment=WebEnvironment.RANDOM_PORT,
	classes={
		SpringsUtilHttpConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
	}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@SuppressWarnings({"nls"})
@Slf4j
public class AbstractIT {
	@LocalServerPort
	private long localServerPort;

	@Value("${server.address}")
	private String serverAddress;

	@Autowired
	private RestTemplate httpRestTemplate;

	private String httpBaseUrl;
	private String httpsBaseUrl;

	@BeforeEach
	public void beforeEach() {
		this.httpBaseUrl  = "http://"  + this.serverAddress + ":" + this.localServerPort;
		this.httpsBaseUrl = "https://" + this.serverAddress + ":" + this.localServerPort;
	}

	@EnableAutoConfiguration
    static class AbstractITConfiguration {
		// do nothing
    }
}
