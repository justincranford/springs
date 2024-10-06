package com.github.justincranford.springs.service.webauthn;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.github.justincranford.springs.util.certs.tls.TomcatTlsInitializer;

import lombok.Getter;
import lombok.experimental.Accessors;

@SpringBootTest(
	webEnvironment = WebEnvironment.RANDOM_PORT,
	classes={
		SpringsServiceWebauthnConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
	}
)
@ContextConfiguration(
	initializers={TomcatTlsInitializer.class}
)
@Import({AbstractIT.MyRestController.class})
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@SuppressWarnings({"nls", "static-method"})
public class AbstractIT {
	protected static final String HTTP_ROOT_RESPONSE_BODY = "Hello world";

	@LocalServerPort
	private long localServerPort;

	@Value("${server.address}")
	private String serverAddress;

	@Autowired
	private RestTemplate tlsMutualAuthenticationRestTemplate;

	@Autowired
	private RestTemplate tlsServerAuthenticationRestTemplate;

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

	@RestController
	@RequestMapping("/")
	public static class MyRestController {
		@GetMapping
		public String helloWorld() {
			return HTTP_ROOT_RESPONSE_BODY;
		}
	}
}
