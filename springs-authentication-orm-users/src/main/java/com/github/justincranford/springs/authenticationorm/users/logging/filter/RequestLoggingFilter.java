package com.github.justincranford.springs.authenticationorm.users.logging.filter;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class RequestLoggingFilter extends OncePerRequestFilter {
	private static final AtomicInteger REQUEST_NUMBER = new AtomicInteger(0);

	@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final int requestNumber = REQUEST_NUMBER.incrementAndGet();
		request.setAttribute("requestId", requestNumber);
        log.info("Request Number: {}", requestNumber);
        filterChain.doFilter(request, response);
    }
}