package com.github.justincranford.springs.service.webauthn.config;

import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.data.envers.repository.support.EnversRevisionRepositoryFactoryBean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.DelegatingPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import com.github.justincranford.springs.persistenceorm.base.config.SpringsPersistenceOrmBaseConfiguration;
import com.github.justincranford.springs.service.webauthn.authenticate.config.AuthenticationConfiguration;
import com.github.justincranford.springs.service.webauthn.credential.config.CredentialConfiguration;
import com.github.justincranford.springs.service.webauthn.register.config.RegistrationConfiguration;
import com.github.justincranford.springs.service.webauthn.relyingparty.config.RelyingPartyConfiguration;
import com.github.justincranford.springs.util.certs.config.SpringsUtilHttpsConfiguration;
import com.github.justincranford.springs.util.json.config.SpringsUtilJsonConfiguration;

import io.micrometer.observation.annotation.Observed;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

@Configuration
@EnableAutoConfiguration(
	exclude = {
		UserDetailsServiceAutoConfiguration.class
	}
)
@EnableConfigurationProperties
@EnableJpaRepositories(
	basePackageClasses = {},
	repositoryFactoryBeanClass = EnversRevisionRepositoryFactoryBean.class
)
@Import(value = {
    SpringsPersistenceOrmBaseConfiguration.class,
	SpringsUtilHttpsConfiguration.class,
	SpringsUtilJsonConfiguration.class,
	CredentialConfiguration.class,
	RegistrationConfiguration.class,
	AuthenticationConfiguration.class,
	RelyingPartyConfiguration.class
})
@Slf4j
@SuppressWarnings({"static-method", "deprecation"})
public class SpringsServiceWebauthnConfiguration {
	@Bean
	@ConditionalOnMissingBean(PasswordEncoder.class)
	public PasswordEncoder passwordEncoder() {
		final Map<String, PasswordEncoder> encoders = Map.of(
			"SHA-256", new org.springframework.security.crypto.password.MessageDigestPasswordEncoder("SHA-256"),
			"pbkdf2",  Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_5(),
			"argon2",  Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2(),
			"bcrypt", new BCryptPasswordEncoder()
		);
		return new DelegatingPasswordEncoder(encoders.keySet().iterator().next(), encoders);
	}

	@Builder
	@Getter
	@Setter
	public static class MyUserPass implements UserDetails {
		private static final long serialVersionUID = 1L;
		private String username;
		private String password;
		private Collection<? extends GrantedAuthority> authorities;
	}

	@Observed
	@Bean
	@ConditionalOnMissingBean(UserDetailsService.class)
	@SuppressWarnings({"resource"})
	public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) throws Exception {
		final InMemoryUserDetailsManager userDetailsService = new InMemoryUserDetailsManager();
		final LinkedBlockingQueue<UserDetails> users = new LinkedBlockingQueue<>();
		final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
		executor.submit(() -> users.add(MyUserPass.builder().username("user").password(passwordEncoder.encode("userPwd")).authorities(Set.of(new SimpleGrantedAuthority("ROLE_USER"))).build()));
		executor.submit(() -> users.add(MyUserPass.builder().username("operator").password(passwordEncoder.encode("operatorPwd")).authorities(Set.of(new SimpleGrantedAuthority("OPERATOR"))).build()));
		executor.submit(() -> users.add(MyUserPass.builder().username("auditor").password(passwordEncoder.encode("auditorPwd")).authorities(Set.of(new SimpleGrantedAuthority("AUDITOR"))).build()));
		executor.submit(() -> users.add(MyUserPass.builder().username("reporter").password(passwordEncoder.encode("reporterPwd")).authorities(Set.of(new SimpleGrantedAuthority("REPORTER"))).build()));
		executor.submit(() -> users.add(MyUserPass.builder().username("admin").password(passwordEncoder.encode("adminPwd")).authorities(Set.of(new SimpleGrantedAuthority("ADMIN"))).build()));
        executor.shutdown();
        executor.awaitTermination(10, TimeUnit.SECONDS);
        users.forEach(userDetails -> userDetailsService.createUser(userDetails));
		return userDetailsService;
	}

	@Order(1)
    @Bean
    public SecurityFilterChain helloWorldSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/helloworld")
        	.authorizeHttpRequests(authorize -> authorize
    			.anyRequest().permitAll()
			)
            .csrf(csrf -> csrf.disable());
        return http.build();
    }

	@Bean
	@Order(2)
	public SecurityFilterChain securityFilterChainStaticResources(HttpSecurity http) throws Exception {
	    http.securityMatcher("/static/**")
	    	.authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
	    		.requestMatchers("/static/**").permitAll()
	            .anyRequest().authenticated()
	        )
	    	.csrf(csrf -> csrf.disable());
	    return http.build();
	}

    @Bean
	@Order(2)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/admin/**")
            .authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
        		.requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
        		.anyRequest().authenticated()
    		)
            .csrf(csrf -> csrf.disable())
            .formLogin(Customizer.withDefaults());
//            .oauth2Login(Customizer.withDefaults());
        return http.build();
    }

    @Bean
	@Order(3)
    public SecurityFilterChain userSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/user/**")
            .authorizeHttpRequests(authorizeHttpRequestsCustomizer -> authorizeHttpRequestsCustomizer
           		.requestMatchers("/api/v1/user/**").hasRole("USER")
        		.anyRequest().authenticated()
    		)
            .csrf(csrf -> csrf.disable())
            .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
	@Order(4)
    public SecurityFilterChain registerSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/register/**")
        	.authorizeHttpRequests(authorize -> authorize
    			.anyRequest().permitAll()
			)
            .csrf(csrf -> csrf.disable());
        return http.build();
    }

	@Order(5)
    @Bean
    public SecurityFilterChain authenticateSecurityFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/authenticate/**")
        	.authorizeHttpRequests(authorize -> authorize
    			.anyRequest().permitAll()
			)
            .csrf(csrf -> csrf.disable());
        return http.build();
    }

	@Bean
	public String httpBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpBaseUrl = "http://"  + serverAddress + ":" + serverPort;
		log.info("httpBaseUrl: {}", httpBaseUrl);
		return httpBaseUrl;
	}

	@Bean
	public String httpsBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpsBaseUrl = "https://"  + serverAddress + ":" + serverPort;
		log.info("httpsBaseUrl: {}", httpsBaseUrl);
		return httpsBaseUrl;
	}
}
