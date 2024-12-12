package com.github.justincranford.springs.server.authentication.client.filter;

import com.github.justincranford.springs.server.authentication.client.token.BearerUnauthenticatedToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
public final class BearerTokenAuthenticationFilter extends OncePerRequestFilter {
    private static final AntPathRequestMatcher ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/api/v1/**");

    private final AuthenticationManager authenticationManager;

    public BearerTokenAuthenticationFilter(final AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * @see org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter#attemptAuthentication
     * @see org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter#attemptAuthentication
     * @see org.springframework.security.web.authentication.www.BasicAuthenticationFilter#doFilterInternal
//   * @see org.springframework.security.oauth2.provider.endpoint.OAuth2TokenEndpointFilter
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        final String method = request.getMethod();
        final String path = request.getServletPath();
        final String pathInfo = request.getPathInfo();
        final BearerUnauthenticatedToken bearerUnauthenticatedToken = convert(request);
        final boolean hasBearerToken = bearerUnauthenticatedToken != null;
        if (!ANT_PATH_REQUEST_MATCHER.matches(request)) {
            log.trace("HTTP method [{}] path [{}] pathInfo [{}] hasBearerToken [{}] no filter match", method, path, pathInfo, hasBearerToken);
        } else if (!hasBearerToken) {
            log.trace("HTTP method [{}] path [{}] pathInfo [{}] hasBearerToken [false] no bearer token", method, path, pathInfo);
        } else {
            log.trace("HTTP method [{}] path [{}] pathInfo [{}] hasBearerToken [true] match", method, path, pathInfo);
            try {
                final Authentication authenticated = this.authenticationManager.authenticate(bearerUnauthenticatedToken);
                SecurityContextHolder.getContext().setAuthentication(authenticated);
            } catch (AuthenticationException ex) {
                SecurityContextHolder.clearContext();
            }
        }
        chain.doFilter(request, response);
    }

    private static @Nullable BearerUnauthenticatedToken convert(final HttpServletRequest request) {
        final String authorizationHeader = request.getHeader("Authorization");
        if (!isBearerAuthentication(authorizationHeader)) {
            log.trace("HTTP authorization header bearer scheme not found");
            return null;
        }
        final String bearerToken = bearerToken(authorizationHeader);
        if (bearerToken == null) {
            log.trace("HTTP bearer token not found");
            return null;
        }
        return new BearerUnauthenticatedToken(bearerToken);
    }

    private static @Nullable String bearerToken(final String authorizationHeader) {
        final String bearerToken = authorizationHeader.substring(7);
        if (bearerToken.isEmpty()) {
            log.trace("Authorization header bearer token is empty");
            return null;
        } else if (bearerToken.isBlank()) {
            log.trace("Authorization header bearer token is blank");
            return null;
        }
        log.trace("Authorization header bearer token is present");
        return bearerToken;
    }

    private static boolean isBearerAuthentication(final String authorizationHeader) {
        if (authorizationHeader == null) {
            log.trace("Authorization header is null");
            return false;
        } else if (authorizationHeader.isEmpty()) {
            log.trace("Authorization header is empty");
            return false;
        } else if (authorizationHeader.isBlank()) {
            log.trace("Authorization header is blank");
            return false;
        } else if (!(authorizationHeader.startsWith("Bearer "))) {
            log.trace("Authorization header doesn't start with 'Bearer '");
            return false;
        }
        return true;
    }
}
