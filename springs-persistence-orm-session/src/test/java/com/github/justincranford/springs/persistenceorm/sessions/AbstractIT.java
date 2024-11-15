package com.github.justincranford.springs.persistenceorm.sessions;

import javax.net.ssl.SSLContext;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.context.WebServerApplicationContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.justincranford.springs.persistenceorm.base.properties.SpringsPersistenceOrmBaseProperties;
import com.github.justincranford.springs.persistenceorm.sessions.config.SpringsPersistenceOrmSessionsConfiguration;
import com.github.justincranford.springs.persistenceorm.sessions.database.repository.SessionOrmRepository;
import com.github.justincranford.springs.persistenceorm.sessions.service.PersonService;
import com.github.justincranford.springs.persistenceorm.sessions.service.repository.SessionPojoRepository;
import com.github.justincranford.springs.persistenceorm.users.person.PersonOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.persona.PersonaOrmRepository;
import com.github.justincranford.springs.persistenceorm.users.properties.SpringsPersistenceOrmUsersPeopleProperties;
import com.github.justincranford.springs.service.http.client.config.SpringsUtilHttpClientConfiguration;
import com.github.justincranford.springs.util.certs.client.config.SpringsUtilHttpsClientsConfiguration;
import com.github.justincranford.springs.util.certs.client.config.SpringsUtilTlsClientsConfiguration;
import com.github.justincranford.springs.util.certs.server.TlsInitializer;
import com.github.justincranford.springs.util.json.config.PrettyJson;

import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.experimental.Accessors;
import lombok.extern.slf4j.Slf4j;

@SpringBootTest(
    webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
    classes = {
		SpringsPersistenceOrmSessionsConfiguration.class,
		AbstractIT.AbstractITConfiguration.class
    }
)
@ContextConfiguration(
	initializers={TlsInitializer.class}
)
@Getter
@Accessors(fluent = true)
@ActiveProfiles({"test"})
@Slf4j
@SuppressWarnings({"static-method"})
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
    private MeterRegistry meterRegistry;
    @Autowired
    private ApplicationContext applicationContext;
    @Autowired
    private PersonOrmRepository personOrmRepository;
    @Autowired
    private PersonaOrmRepository personaOrmRepository;
    @Autowired
    private SessionOrmRepository sessionOrmRepository;
    @Autowired
    private SpringsPersistenceOrmBaseProperties springsPersistenceOrmBaseProperties;
    @Autowired
    private SpringsPersistenceOrmUsersPeopleProperties springsPersistenceOrmUsersPeopleProperties;
    @Autowired
    private HttpSecurity http;
	@Autowired
	private SessionPojoRepository repository;

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

	@Configuration
	public static class AbstractITConfiguration {
    	/**
    	 * @see org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity
    	 */
    	@Primary
        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
            http.securityMatcher("/**")
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                    .requestMatchers("/**").permitAll()
                )
                .csrf(csrf -> csrf.disable())
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
    			.requestCache(cache -> cache
					.disable() // skip serdes DefaultSavedRequest to SessionRepository Session.attributes
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
}
