package com.github.justincranford.springs.authenticationorm.users.authentication.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;

import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonUsernamePasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.authentication.provider.PersonaEmailPasswordAuthenticationProvider;
import com.github.justincranford.springs.authenticationorm.users.config.RateLimitingFilter;
import com.github.justincranford.springs.service.http.server.HelloWorldController;

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
	HelloWorldController.class
})
@RequiredArgsConstructor
@Slf4j
@SuppressWarnings({"nls", "static-method"})
public class SpringsAuthenticationOrmUsersSecurityFilterChainConfiguration {
	@Autowired
	private final PersonaEmailPasswordAuthenticationProvider personaEmailPasswordAuthenticationProvider;
	@Autowired
	private final PersonUsernamePasswordAuthenticationProvider	 personUsernamePasswordAuthenticationProvider;

	@Bean
	public AuthenticationManager htmlAuthenticationManager(HttpSecurity http) throws Exception {
		final AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		return authenticationManagerBuilder
			.authenticationProvider(this.personaEmailPasswordAuthenticationProvider)
			.authenticationProvider(this.personUsernamePasswordAuthenticationProvider)
			.build();
	}

	@Primary
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    	// STATELESS API AUTHENTICATION WITHOUT SESSIONS
        http.securityMatcher("/static/**", "/v1/api/authenticate/**", "/v1/api/register/**", "/helloworld", "/v1/api/**")
            .csrf(csrf -> csrf.disable()) // Typically disabled for stateless APIs
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/static/**", "/v1/api/authenticate/**", "/v1/api/register/**", "/helloworld").permitAll()
                .requestMatchers("/v1/api/**").authenticated()
            )
            .httpBasic(Customizer.withDefaults())
            .sessionManagement(management -> management
        		.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
    		)
			.addFilterBefore(new RateLimitingFilter(), UsernamePasswordAuthenticationFilter.class)
            ;

        // STATEFUL HTML AUTHENTICATION AND SESSIONS
        http.securityMatcher("/secure/**")
        	.csrf(csrf -> csrf
				.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
			)
            .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                .requestMatchers("/secure/**").authenticated()
            )
			.httpBasic(basic -> basic
				.disable()
			)
            .formLogin(form -> form
                .loginPage("/login")
                .permitAll()
				.defaultSuccessUrl("/home", true)
				.failureUrl("/login?error=true")
            )
			.logout(logout -> logout
				.logoutUrl("/logout")
                .permitAll()
				.logoutSuccessUrl("/login?logout=true")
				.invalidateHttpSession(true)
            )
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
				.maximumSessions(3)
				.expiredUrl("/login?expired=true")
			)
			.addFilterBefore(new RateLimitingFilter(), UsernamePasswordAuthenticationFilter.class)
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
