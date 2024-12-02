package com.github.justincranford.springs.server.authentication.client.filter;

import com.github.justincranford.springs.server.authentication.client.token.ClientJwtUnauthenticatedToken;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTParser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;

@Component
@Slf4j
public final class ClientJwtBearerTokenAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(final HttpServletRequest request, final HttpServletResponse response, final FilterChain filterChain) throws ServletException, IOException {
        if (jwt(request) instanceof JWT jwt) {
            SecurityContextHolder.getContext().setAuthentication(new ClientJwtUnauthenticatedToken(jwt));
        }
        filterChain.doFilter(request, response);
    }

    private JWT jwt(final HttpServletRequest request) {
        final String bearerToken = bearer(request);
        if (bearerToken == null) {
            log.trace("No bearer token");
            return null;
        }
        try {
            return JWTParser.parse(bearerToken); // PlainJWT, SignedJWT, or EncryptedJWT
        } catch (ParseException e) {
            log.trace("Not a JWT", e);
            return null;
        }
    }

    private String bearer(final HttpServletRequest request) {
        final String authorization = request.getHeader("Authorization");
        if ((authorization != null) && (authorization.startsWith("Bearer "))) {
            final String bearerToken = authorization.substring(7);
            if (!bearerToken.isBlank()) { // check if empty or all whitespace
                return bearerToken;
            }
        }
        return null;
    }
}
