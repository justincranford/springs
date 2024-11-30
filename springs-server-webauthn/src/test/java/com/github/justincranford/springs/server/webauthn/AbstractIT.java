package com.github.justincranford.springs.server.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.server.webauthn.config.SpringsServerWebauthnConfiguration;
import com.github.justincranford.springs.util.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.http.server.helloworld.HelloWorldController;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilTlsClientsConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.TlsEnabledByDefaultApplicationContextInitializer;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

// TODO RANDOM_PORT
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes={
		SpringsServerWebauthnConfiguration.class
	}
)
@ContextConfiguration(
	initializers={
		TlsEnabledByDefaultApplicationContextInitializer.class,
	    BootstrapTestContainersApplicationContextInitializer.class
	}
)
@Import({HelloWorldController.class})
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
public class AbstractIT {
	@PostConstruct
	public void postConstruct() {
		this.httpBaseUrl     = "http://"  + serverAddress() + ":" + localServerPort();
		this.httpsBaseUrl    = "https://" + serverAddress() + ":" + localServerPort();
		this.httpsPskBaseUrl = "https://" + serverAddress() + ":" + 9443;
		log.info("urls, httpBaseUrl: {}, httpsBaseUrl: {}, httpsPskBaseUrl: {}", this.httpBaseUrl, this.httpsBaseUrl, this.httpsPskBaseUrl);
	}

	@Value("${server.address}")
	private String serverAddress;

	@LocalServerPort
	private long localServerPort;

	@Autowired
	private String httpBaseUrl;

	@Autowired
	private String httpsBaseUrl;

    @Autowired
    private String httpsPskBaseUrl;

	@Autowired
	private WebServerApplicationContext webServerApplicationContext;
	@Autowired
	@Qualifier("httpRestTemplate")
	private RestTemplate httpRestTemplate; /** @see SpringsUtilHttpClientConfiguration#httpRestTemplate */

	@Autowired(required=false)
	@Qualifier("mtlsRestTemplate")
	private RestTemplate mtlsRestTemplate; /** @see SpringsUtilHttpsClientsConfiguration#mtlsRestTemplate */

	@Autowired(required=false)
	@Qualifier("stlsRestTemplate")
	private RestTemplate stlsRestTemplate; /** @see SpringsUtilHttpsClientsConfiguration#stlsRestTemplate */

	@Autowired(required=false)
	@Qualifier("ptlsRestTemplate")
	private RestTemplate ptlsRestTemplate; /** @see SpringsUtilHttpsClientsConfiguration#ptlsRestTemplate */

	@Autowired(required=false)
	@Qualifier("stlsSslContext")
	private SSLContext stlsSslContext; /** @see SpringsUtilTlsClientsConfiguration#stlsSslContext */

	@Autowired(required=false)
	@Qualifier("mtlsSslContext")
	private SSLContext mtlsSslContext; /** @see SpringsUtilTlsClientsConfiguration#mtlsSslContext */

	@Autowired(required=false)
	@Qualifier("ptlsSslContext")
	private SSLContext ptlsSslContext; /** @see SpringsUtilTlsClientsConfiguration#ptlsSslContext */

	@Autowired
	private ObjectMapper objectMapper;

	@DynamicPropertySource
	static void properties(final DynamicPropertyRegistry registry) {
		registry.add("bootstrap.testcontainers.mode",                 () -> "preferred");
		registry.add("bootstrap.testcontainers.containers.postgres1", () -> "postgres:16.3");
	}
}
