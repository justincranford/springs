package com.github.justincranford.springs.util.certs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.service.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.certs.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.certs.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.certs.server.TomcatTlsInitializer;

import lombok.Getter;
import lombok.experimental.Accessors;

@SpringBootTest(
	webEnvironment = WebEnvironment.RANDOM_PORT,
	classes={
		SpringsUtilHttpsConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
	}	
)
// TODO Fix configuration so this isn't needed
@ContextConfiguration(
	initializers={TomcatTlsInitializer.class}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@SuppressWarnings({"static-method"})
public class AbstractIT {
	@LocalServerPort
	private long localServerPort;

	@Value("${" + TomcatTlsInitializer.SslAutoConfigPropertyNames.ENABLED + ":false}")
	private boolean sslAutoConfigEnabled;

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

    @Configuration
	@EnableAutoConfiguration(exclude = { UserDetailsServiceAutoConfiguration.class })
    static class AbstractITConfiguration {
	    @Bean
	    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
	        http
	        	.authorizeHttpRequests(authz -> authz.anyRequest().permitAll())
	        	.csrf(csrf -> csrf.disable());
	        return http.build();
	    }
    }
}
