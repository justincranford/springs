package com.github.justincranford.springs.persistenceredis.sessions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.users.person.service.PersonService;
import com.github.justincranford.springs.persistenceredis.config.SpringsPersistenceRedisSessionsConfiguration;
import com.github.justincranford.springs.persistenceredis.properties.RedisProperties;
import com.github.justincranford.springs.util.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.https.client.config.SpringsUtilTlsClientsConfiguration;
import com.github.justincranford.springs.util.https.server.bootstrap.TlsEnabledByDefaultApplicationContextInitializer;
import com.github.justincranford.springs.util.json.config.PrettyJson;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainers;
import com.github.justincranford.springs.util.testcontainers.bootstrap.BootstrapTestContainersApplicationContextInitializer;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.SSLContext;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    classes = {
		SpringsPersistenceRedisSessionsConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
    }
)
@ContextConfiguration(
	initializers={
		TlsEnabledByDefaultApplicationContextInitializer.class,
		BootstrapTestContainersApplicationContextInitializer.class
	}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"static-method"})
public class AbstractIT {
    @Autowired
    private String httpBaseUrl;

    @Autowired
    private String httpsBaseUrl;

    @Autowired
    private String httpsPskBaseUrl;

    @Autowired
    private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
    @Autowired
    private HttpSecurity http;

	@Autowired
	private WebServerApplicationContext webServerApplicationContext;

	@Autowired
	private SslBundles sslBundles;

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

	@Autowired
	private PrettyJson prettyJson;

	@Autowired
	private RedisProperties redisProperties;


	@TestConfiguration
	@Slf4j
	public static class AbstractITConfiguration {
		/**
//    	 * @see org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity
    	 */
    	@Primary
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.securityMatcher("/**")
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                    .requestMatchers("/**").permitAll()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(Customizer.withDefaults())
    			.sessionManagement(session -> session
    				.sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
    				.maximumSessions(3)
    			)
    			.logout(logout -> logout
	                .permitAll()
					.logoutSuccessUrl("/helloworld?logout=true")
					.invalidateHttpSession(true)
	            )
    			.requestCache(RequestCacheConfigurer::disable // skip serdes DefaultSavedRequest to SessionRepository Session.attributes
				)
                ;
            return http.build();
    	}

    	@Primary
		@Bean
		public UserDetailsService userDetailsService(final PersonService personService) {
    		return personService;
		}
	}

	@DynamicPropertySource
	static void redisServerContainer(final DynamicPropertyRegistry registry) {
		registry.add(BootstrapTestContainers.Properties.ENABLED,                             () -> BootstrapTestContainers.Properties.ENABLE.PREFERRED);
		registry.add(BootstrapTestContainers.Properties.CONTAINERS_PREFIX + "redis1", () -> "redis:7.4.0");
	}
}
