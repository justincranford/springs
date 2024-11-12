package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonaEmailPasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.root.controller.RedirectController;
import com.github.justincranford.springs.authenticationorm.users.logging.config.RequestLoggingFilter;
import com.github.justincranford.springs.authenticationorm.users.ratelimit.config.RateLimitingFilter;
import com.github.justincranford.springs.service.http.server.HelloWorldController;
import com.github.justincranford.springs.service.http.server.RedirectToLoginConfigurer;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * @see org.springframework.security.config.annotation.web.builders.FilterOrderRegistration
 */
@Configuration
@EnableAutoConfiguration(
	exclude = {
		UserDetailsServiceAutoConfiguration.class
	}
)
@EnableWebSecurity
//@EnableMethodSecurity(prePostEnabled=true, securedEnabled=true, jsr250Enabled=true)
@Import(value = {
	HelloWorldController.class,
	RedirectController.class,
	RedirectToLoginConfigurer.class
})
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"static-method"})
public class SpringsAuthenticationOrmUsersSecurityFilterChainConfiguration {
	@Autowired
	private final PersonaEmailPasswordAuthenticationProvider personaEmailPasswordAuthenticationProvider;
	@Autowired
	private final PersonUsernamePasswordAuthenticationProvider personUsernamePasswordAuthenticationProvider;
	@Autowired
	private final RateLimitingFilter rateLimitingFilter;
	@Autowired
	private final RequestLoggingFilter requestLoggingFilter;

	@Bean
	public AuthenticationManager htmlAuthenticationManager(HttpSecurity http) throws Exception {
		final AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		return authenticationManagerBuilder
			.authenticationProvider(this.personaEmailPasswordAuthenticationProvider)
			.authenticationProvider(this.personUsernamePasswordAuthenticationProvider)
			.parentAuthenticationManager(null) // Prevent ProviderManager recursively calling `this.parent.authenticate(authentication)`
			.build();
	}

	@Primary
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    	// STATELESS API AUTHENTICATION WITHOUT SESSIONS
        http.securityMatcher("/static/**", "/public/**", "/templates/**", "/META-INF/resources/**", "/helloworld", "/v1/api/authenticate/**", "/v1/api/register/**", "/v1/api/**")
            .csrf(csrf -> csrf.disable()) // Typically disabled for stateless APIs
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/static/**", "/public/**", "/templates/**", "/META-INF/resources/**", "/helloworld", "/v1/api/authenticate/**", "/v1/api/register/**").permitAll()
                .requestMatchers("/v1/api/**").authenticated()
            )
            .httpBasic(Customizer.withDefaults())
            .sessionManagement(management -> management
        		.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    		)
			.addFilterBefore(this.rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
            ;

        // STATEFUL HTML AUTHENTICATION AND SESSIONS
        http.securityMatcher("/login", "/logout", "/secure/**")
        	.csrf(csrf -> csrf
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			)
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/login", "/logout").permitAll()
                .requestMatchers("/secure/**").authenticated()
            )
			.httpBasic(basic -> basic
				.disable()
			)
            .formLogin(form -> form
//                .loginPage("/login")
                .permitAll()
				.defaultSuccessUrl("/secure/home", true)
//				.failureUrl("/login?error=true")
            )
			.logout(logout -> logout
//				.logoutUrl("/logout")
                .permitAll()
				.logoutSuccessUrl("/login?logout=true")
				.invalidateHttpSession(true)
            )
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.maximumSessions(3)
				.expiredUrl("/login?expired=true")
			)
			.addFilterBefore(this.requestLoggingFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(this.rateLimitingFilter, UsernamePasswordAuthenticationFilter.class)
//			.addFilterBefore(new BasicAuthenticationFilter(htmlAuthenticationManager(http)), UsernamePasswordAuthenticationFilter.class)
			;

        return http.build();
    }

	@Bean
	public String httpBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpBaseUrl = "http://" + serverAddress + ":" + serverPort;
		log.info("httpBaseUrl: {}", httpBaseUrl);
		return httpBaseUrl;
	}

	@Bean
	public String httpsBaseUrl(
		@Value("${server.address}") final String serverAddress,
		@Value("${server.port}") final long serverPort
	) {
		final String httpsBaseUrl = "https://" + serverAddress + ":" + serverPort;
		log.info("httpsBaseUrl: {}", httpsBaseUrl);
		return httpsBaseUrl;
	}
}
