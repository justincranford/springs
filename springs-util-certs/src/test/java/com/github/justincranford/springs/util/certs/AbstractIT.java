package com.github.justincranford.springs.util.certs;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.client.RestTemplateBuilder;
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
	classes={AbstractIT.AbstractITConfiguration.class},
	webEnvironment = WebEnvironment.RANDOM_PORT
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

	@Autowired
	private RestTemplate tlsMutualAuthenticationRestTemplate;

	@Autowired
	private RestTemplate tlsServerAuthenticationRestTemplate;

	@EnableAutoConfiguration(exclude = { UserDetailsServiceAutoConfiguration.class })
    @EnableConfigurationProperties
    @Configuration
    static class AbstractITConfiguration {
		@Bean
    	public RestTemplate tlsMutualAuthenticationRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
	        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.CLIENT_BUNDLE_MUTUAL_AUTHENTICATION);
    		return restTemplateBuilder
				.setSslBundle(clientSslBundle)
				.build();
    	}

		@Bean
    	public RestTemplate tlsServerAuthenticationRestTemplate(final RestTemplateBuilder restTemplateBuilder, final SslBundles sslBundles) {
	        final SslBundle clientSslBundle = sslBundles.getBundle(TomcatTlsInitializer.CLIENT_BUNDLE_SERVER_AUTHENTICATION);
    		return restTemplateBuilder
				.setSslBundle(clientSslBundle)
				.build();
    	}

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
