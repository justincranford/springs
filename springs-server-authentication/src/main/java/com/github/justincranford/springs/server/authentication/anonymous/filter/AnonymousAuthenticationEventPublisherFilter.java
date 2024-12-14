package com.github.justincranford.springs.server.authentication.anonymous.filter;

import com.github.justincranford.springs.server.authentication.anonymous.event.AnonymousAuthenticationEvent;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public final class AnonymousAuthenticationEventPublisherFilter extends OncePerRequestFilter {
    private final ApplicationEventPublisher applicationEventPublisher;

    /**
     * @see org.springframework.security.authentication.ProviderManager#authenticate 
     * @see org.springframework.security.web.authentication.AnonymousAuthenticationFilter#doFilter     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof AnonymousAuthenticationToken) {
            this.applicationEventPublisher.publishEvent(new AnonymousAuthenticationEvent(this, authentication));
        }
        chain.doFilter(request, response);
    }
}
