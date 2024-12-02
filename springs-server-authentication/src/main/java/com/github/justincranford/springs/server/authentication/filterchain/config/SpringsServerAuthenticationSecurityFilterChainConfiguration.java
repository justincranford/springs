package com.github.justincranford.springs.server.authentication.filterchain.config;

import com.github.justincranford.springs.server.authentication.client.filter.ClientJwtBearerTokenAuthenticationFilter;
import com.github.justincranford.springs.server.authentication.client.provider.ClientJwtAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.client.provider.ClientNameSecretAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.filterchain.redirect.CustomAuthenticationEntryPoint;
import com.github.justincranford.springs.server.authentication.redirect.controller.RedirectController;
import com.github.justincranford.springs.server.authentication.user.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.server.authentication.user.provider.PersonaEmailPasswordAuthenticationProvider;
import com.github.justincranford.springs.util.http.server.helloworld.HelloWorldController;
import com.github.justincranford.springs.util.http.server.logging.filter.RequestLogFilter;
import com.github.justincranford.springs.util.http.server.ratelimit.filter.RateLimitFilter;
import com.github.justincranford.springs.util.http.server.redirect.RedirectToLoginConfigurer;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

/**
// * @see org.springframework.security.config.annotation.web.builders.FilterOrderRegistration
 */
@Configuration
@EnableAutoConfiguration
@EnableWebSecurity
//@EnableMethodSecurity(prePostEnabled=true, securedEnabled=true, jsr250Enabled=true)
@Import(value = {
	HelloWorldController.class,
	RedirectController.class,
//	LoginController.class,
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
	private final ClientJwtBearerTokenAuthenticationFilter clientJwtBearerTokenAuthenticationFilter;
	@Autowired
	private final ClientJwtAuthenticationProvider clientJwtAuthenticationProvider;

	@Autowired
	private final RateLimitFilter rateLimitingFilter;
	@Autowired
	private final RequestLogFilter requestLoggingFilter;

	@Primary
	@Bean
	public AuthenticationManager htmlAuthenticationManager(HttpSecurity http) throws Exception {
		final AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		return authenticationManagerBuilder
			.authenticationProvider(this.personaEmailPasswordAuthenticationProvider)
			.authenticationProvider(this.personUsernamePasswordAuthenticationProvider)
			.authenticationProvider(this.clientNameSecretAuthenticationProvider)
			.authenticationProvider(this.clientJwtAuthenticationProvider)
			.parentAuthenticationManager(null) // Prevent ProviderManager recursively calling `this.parent.authenticate(authentication)`
			.build();
	}

	/**
//	 * @see org.springframework.security.config.annotation.web.configuration.HttpSecurityConfiguration#httpSecurity
	 //              .loginPage("/login").failureUrl("/login?error=true")
	 //				.logoutUrl("/logout").deleteCookies("JSESSIONID")
	 */
    @Bean
    public SecurityFilterChain securityFilterChainUserUi(HttpSecurity http) throws Exception {
		http.securityMatcher("/login", "/logout", "/secure/**")
			.authorizeHttpRequests(authz -> authz
				.requestMatchers("/login", "/logout").permitAll()
				.requestMatchers("/secure/**").authenticated()
			)
			.csrf(csrf -> csrf
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			)
			.httpBasic(AbstractHttpConfigurer::disable)
			.formLogin(form -> form
			    .permitAll()
				.defaultSuccessUrl("/secure/home", true)
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
			.addFilterBefore(this.requestLoggingFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(this.rateLimitingFilter, UsernamePasswordAuthenticationFilter.class);

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
			.addFilterBefore(this.requestLoggingFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(this.rateLimitingFilter,   UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	@Bean
	public SecurityFilterChain securityFilterChainApi(HttpSecurity http) throws Exception {
        http.securityMatcher("/v1/api/**")
            .authorizeHttpRequests(authz -> authz
				.requestMatchers("/v1/api/authenticate/**", "/v1/api/register/**").permitAll()
				.requestMatchers("/v1/api/**").authenticated()
			)
			.csrf(AbstractHttpConfigurer::disable) // Typically disabled for stateless APIs
            .httpBasic(Customizer.withDefaults())
			.exceptionHandling(exception -> exception
				.authenticationEntryPoint(new CustomAuthenticationEntryPoint("/v1/api/authentication/status"))
			)
            .sessionManagement(management -> management
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)
			.addFilterBefore(this.requestLoggingFilter, UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(this.rateLimitingFilter,   UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(this.clientJwtBearerTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
