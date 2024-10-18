package com.github.justincranford.springs.service.webauthn;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.service.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.service.http.server.HelloWorldController;
import com.github.justincranford.springs.service.webauthn.config.SpringsServiceWebauthnConfiguration;
import com.github.justincranford.springs.util.certs.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.certs.server.TomcatTlsInitializer;

import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

// TODO RANDOM_PORT
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes={
		SpringsServiceWebauthnConfiguration.class
	}
)
@ContextConfiguration(
	initializers={TomcatTlsInitializer.class}
)
@Import({HelloWorldController.class})
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
public class AbstractIT {
	@LocalServerPort
	private long localServerPort;

	@Value("${server.address}")
	private String serverAddress;

	/**
	 * @see SpringsUtilHttpClientConfiguration#httpRestTemplate
	 */
	@Autowired
	@Qualifier("httpRestTemplate")
	private RestTemplate httpRestTemplate;

	/**
	 * @see SpringsUtilHttpsClientsConfiguration#mtlsRestTemplate
	 */
	@Autowired(required=false)
	@Qualifier("mtlsRestTemplate")
	private RestTemplate mtlsRestTemplate;

	/**
	 * @see SpringsUtilHttpsClientsConfiguration#stlsRestTemplate
	 */
	@Autowired(required=false)
	@Qualifier("stlsRestTemplate")
	private RestTemplate stlsRestTemplate;

	@Autowired
	private ObjectMapper objectMapper;

	@Autowired
	private String httpBaseUrl;

	@Autowired
	private String httpsBaseUrl;
}
