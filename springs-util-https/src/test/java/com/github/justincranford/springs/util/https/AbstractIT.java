package com.github.justincranford.springs.util.https;

import com.github.justincranford.springs.util.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilTlsClientsConfiguration;
import com.github.justincranford.springs.util.https.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.BootstrapTls;
import com.github.justincranford.springs.util.https.server.bootstrap.BootstrapTlsApplicationContextInitializer;
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
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

@SpringBootTest(
	webEnvironment = WebEnvironment.RANDOM_PORT,
	classes={
		SpringsUtilHttpsConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
	}
)
@ContextConfiguration(
	initializers={BootstrapTlsApplicationContextInitializer.class}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@SuppressWarnings({"static-method"})
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

	@Value("${" + BootstrapTls.SslAutoConfigPropertyNames.ENABLED + ":false}")
	private boolean sslAutoConfigEnabled;

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

    @Configuration
    static class AbstractITConfiguration {
	    @Bean
	    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	        return http.authorizeHttpRequests(authz -> authz.anyRequest().permitAll()).csrf(AbstractHttpConfigurer::disable).build();
	    }
    }
}
