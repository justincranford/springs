package com.github.justincranford.springs.server.authentication.filterchain.config;

import com.github.justincranford.springs.server.authentication.anonymous.filter.AnonymousAuthenticationEventPublisherFilter;
import com.github.justincranford.springs.server.authentication.client.filter.BearerTokenAuthenticationFilter;
import com.github.justincranford.springs.server.authentication.client.provider.ClientJwtAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.client.provider.ClientNameSecretAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.filterchain.redirect.CustomAuthenticationEntryPoint;
import com.github.justincranford.springs.server.authentication.ui.controller.UiController;
import com.github.justincranford.springs.server.authentication.user.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.user.provider.PersonaEmailPasswordAuthenticationProvider;
import com.github.justincranford.springs.util.http.server.helloworld.HelloWorldController;
import com.github.justincranford.springs.util.http.server.logging.filter.RequestLogFilter;
import com.github.justincranford.springs.util.http.server.ratelimit.filter.RateLimitFilter;
import com.github.justincranford.springs.util.http.server.redirect.RedirectToLoginConfigurer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.session.DisableEncodeUrlFilter;

/**
 * @see org.springframework.web.filter.DelegatingFilterProxy#doFilter
 * @see org.springframework.security.web.FilterChainProxy#doFilter
// * @see org.springframework.security.web.FilterChainProxy.VirtualFilterChain#doFilter
 * @see org.springframework.security.config.annotation.web.builders.FilterOrderRegistration
 */
@Configuration
@EnableAutoConfiguration
@EnableWebSecurity
//@EnableMethodSecurity(prePostEnabled=true, securedEnabled=true, jsr250Enabled=true)
@Import(value = {
	HelloWorldController.class,
	UiController.class,
	RedirectToLoginConfigurer.class
})
@RequiredArgsConstructor
@Slf4j
public class SpringsServerAuthenticationSecurityFilterChainConfiguration {
	@Autowired
	private final PersonaEmailPasswordAuthenticationProvider personaEmailPasswordAuthenticationProvider;
	@Autowired
	private final PersonUsernamePasswordAuthenticationProvider personUsernamePasswordAuthenticationProvider;
	@Autowired
	private final ClientNameSecretAuthenticationProvider clientNameSecretAuthenticationProvider;
	@Autowired
	private final ClientJwtAuthenticationProvider clientJwtAuthenticationProvider;

	@Autowired
	private final RateLimitFilter rateLimitingFilter;
	@Autowired
	private final RequestLogFilter requestLoggingFilter;

	@Value("${server.address}")
	private String serverAddress;

	@Value("${server.port}")
	private Integer serverPort;

	@Primary
	@Bean
	public AuthenticationManager authenticationManager(final HttpSecurity http) throws Exception {
		final AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		return authenticationManagerBuilder
			.authenticationProvider(this.personaEmailPasswordAuthenticationProvider)
			.authenticationProvider(this.personUsernamePasswordAuthenticationProvider)
			.authenticationProvider(this.clientNameSecretAuthenticationProvider)
			.authenticationProvider(this.clientJwtAuthenticationProvider)
			.parentAuthenticationManager(null) // Prevent ProviderManager recursively calling `this.parent.authenticate(authentication)`
			.build();
	}

	@Bean
	public BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter(final AuthenticationManager authenticationManager) {
		return new BearerTokenAuthenticationFilter(authenticationManager);
	}

	@Bean
	public AnonymousAuthenticationEventPublisherFilter anonymousAuthenticationEventPublisherFilter(final ApplicationEventPublisher applicationEventPublisher) {
		return new AnonymousAuthenticationEventPublisherFilter(applicationEventPublisher);
	}

//	@Bean
//	public UserDetailsService userDetailsService(final PersonService personService) {
//		return personService;
//	}
//	@Qualifier("userDetailsService")
	@Primary
	@Bean
	public UserDetailsService webauthnUserDetailsService() {
		return new InMemoryUserDetailsManager();
	}

	@Bean
	public FilterRegistrationBean<BearerTokenAuthenticationFilter> filterRegistrationBeanBearerTokenAuthenticationFilter(final BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter) {
		final FilterRegistrationBean<BearerTokenAuthenticationFilter> filterRegistrationBeanBearerTokenAuthenticationFilter = new FilterRegistrationBean<>(bearerTokenAuthenticationFilter);
		filterRegistrationBeanBearerTokenAuthenticationFilter.setEnabled(false);
		return filterRegistrationBeanBearerTokenAuthenticationFilter;
	}

	/**
//	 * @see org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity
	 //              .loginPage("/login").failureUrl("/login?error=true")
	 //				.logoutUrl("/logout").deleteCookies("JSESSIONID")
	 */
    @Bean
    public SecurityFilterChain securityFilterChainUserUi(HttpSecurity http) throws Exception {
		http.securityMatcher("/login", "/logout", "/default-ui.css", "/login/webauthn.js", "/login/webauthn", "/webauthn/**", "/secure/**")
			.authorizeHttpRequests(authz -> authz
				.requestMatchers("/webauthn/register").authenticated()
				.requestMatchers("/login", "/logout", "/default-ui.css", "/login/webauthn.js", "/login/webauthn", "/webauthn/**").permitAll()
				.requestMatchers("/secure/**").authenticated()
			)
			.csrf(csrf -> csrf
				.csrfTokenRepository(new HttpSessionCsrfTokenRepository())
			)
			.httpBasic(AbstractHttpConfigurer::disable)
			.formLogin(form -> form
				.loginPage("/login")
			    .permitAll()
				.defaultSuccessUrl("/secure/home", true)
			)
			/** @see org.springframework.security.web.webauthn.registration.DefaultWebAuthnRegistrationPageGeneratingFilter#HTML_TEMPLATE */
			/** @see org.springframework.security.web.webauthn.registration.HttpSessionPublicKeyCredentialCreationOptionsRepository */
			/** @see org.springframework.security.web.webauthn.registration.PublicKeyCredentialCreationOptionsFilter */
			/** @see org.springframework.security.web.webauthn.registration.WebAuthnRegistrationFilter */

			/** @see org.springframework.security.web.webauthn.authentication.HttpSessionPublicKeyCredentialRequestOptionsRepository */
			/** @see org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsFilter */
			/** @see org.springframework.security.web.webauthn.authentication.PublicKeyCredentialRequestOptionsRepository */
			/** @see org.springframework.security.web.webauthn.authentication.WebAuthnAuthentication */
			/** @see org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter */
			/** @see org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationProvider */
			/** @see org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationRequestToken */

			.webAuthn((webAuthn) -> webAuthn
				.rpName("Springs Server Authentication Relying Party")
				.rpId(this.serverAddress)
				.allowedOrigins("https://" + this.serverAddress + ":" + this.serverPort)
			)
			.logout(logout -> logout
				.permitAll()
				.logoutSuccessUrl("/login?logout")
				.invalidateHttpSession(true)
			)
			.sessionManagement(session -> session
				  .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				  .maximumSessions(3)
				  .expiredUrl("/login?expired")
			)
			.requestCache(RequestCacheConfigurer::disable) // skip serdes DefaultSavedRequest to SessionRepository Session.attributes
			.addFilterBefore(this.requestLoggingFilter, DisableEncodeUrlFilter.class)
			.addFilterBefore(this.rateLimitingFilter, DisableEncodeUrlFilter.class);

		return http.build();
	}

	@Bean
	public SecurityFilterChain securityFilterChainResources(HttpSecurity http) throws Exception {
		http.securityMatcher("/helloworld", "/static/**", "/public/**", "/templates/**", "/META-INF/resources/**")
			.authorizeHttpRequests(authz -> authz
				 .requestMatchers("/helloworld", "/static/**", "/public/**", "/templates/**", "/META-INF/resources/**").permitAll()
			)
			.csrf(AbstractHttpConfigurer::disable) // Typically disabled for stateless APIs
			.sessionManagement(management -> management
				 .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)
			.addFilterBefore(this.requestLoggingFilter, DisableEncodeUrlFilter.class)
			.addFilterBefore(this.rateLimitingFilter,   DisableEncodeUrlFilter.class);

		return http.build();
	}

	@Bean
	public SecurityFilterChain securityFilterChainApi(
		final HttpSecurity http,
		final BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter,
		final AnonymousAuthenticationEventPublisherFilter anonymousAuthenticationEventPublisherFilter
	) throws Exception {
        http.securityMatcher("/api/v1/**")
            .authorizeHttpRequests(authz -> authz
				.requestMatchers("/api/v1/authenticate/**", "/api/v1/register/**").permitAll()
				.requestMatchers("/api/v1/**").authenticated()
			)
			.csrf(AbstractHttpConfigurer::disable) // Typically disabled for stateless APIs
            .httpBasic(Customizer.withDefaults())
			.exceptionHandling(exception -> exception
				.authenticationEntryPoint(new CustomAuthenticationEntryPoint("/api/v1/authentication/status"))
			)
            .sessionManagement(management -> management
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)
			.addFilterBefore(this.requestLoggingFilter, DisableEncodeUrlFilter.class)
			.addFilterBefore(this.rateLimitingFilter,   DisableEncodeUrlFilter.class)
			.addFilterBefore(bearerTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterAfter(anonymousAuthenticationEventPublisherFilter, AnonymousAuthenticationFilter.class)
			;

        return http.build();
    }
}
