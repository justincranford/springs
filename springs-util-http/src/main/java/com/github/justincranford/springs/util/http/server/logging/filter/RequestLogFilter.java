package com.github.justincranford.springs.util.http.server.logging.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.concurrent.atomic.AtomicLong;

@Component
@Slf4j
public class RequestLogFilter extends OncePerRequestFilter {
	private static final AtomicLong REQUEST_NUMBER = new AtomicLong(1);

	@Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final Long requestNumber = REQUEST_NUMBER.getAndIncrement();
		request.setAttribute("X-REQUEST_NUMBER", requestNumber);
        log.debug("X-Request-Number: {}", requestNumber);
		response.addHeader("X-Request-Number", requestNumber.toString());
        filterChain.doFilter(request, response);
    }
}
